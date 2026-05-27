# Layer 2 — The Anchor Layer (Audit & Settlement)

> Keychain's bridge to Ethereum-grade economic security.

## 1. Why an L2

Layer 1 (the BlockDAG) is fast and cheap but lacks the deep economic security of Ethereum mainnet. Layer 2 (an Ethereum L2 rollup) is the **settlement** anchor. The DAG periodically commits its state into L2 smart contracts so that:

- a malicious actor cannot rewrite DAG history without also rewriting an Ethereum-anchored Merkle commitment, and
- every off-chain dispute can be resolved by re-proving against the anchored commitment.

## 2. L2 choice

[ADR-0004](adr/ADR-0004-l2-selection-base-vs-arbitrum.md) selects **Base** for v1, with portable contracts so Arbitrum, Optimism, or a future zk-rollup are drop-in alternatives.

Why Base in v1:
- EIP-4844 blob calldata gives the lowest per-byte cost for high-cadence anchoring.
- Coinbase distribution simplifies the sponsorship onramps that HumanKey's anti-Sybil model relies on (P5).
- Contracts are *behavior-portable* — only deployment scripts and chain IDs change.

## 3. Anchor mechanism

Every DAG epoch (target: ~1 minute), one designated node produces a Merkle accumulator over the epoch's events:

1. Accumulate `eventId` leaves into a Merkle tree of depth `log2(N)`.
2. Compute `dagStateRoot = MerkleRoot(events) || prevEpochRoot`.
3. Produce a ZK proof that the accumulation is correct (this is the same prover used for pruning — see [ADR-0001](adr/ADR-0001-ephemeral-dag-pruning-zk-rollups.md)).
4. Call `IKeychainAnchor.commitEpoch(dagStateRoot, zkProof, epoch)`.

After `commitEpoch` returns, the DAG epoch is **finalized**: any L1 reorganization that would invalidate this epoch's state requires also reorganizing the L2 (and, indirectly, L1 Ethereum at the L2's challenge period).

## 4. The interface

The full surface is in [`interfaces/contracts/IKeychainAnchor.sol`](../interfaces/contracts/IKeychainAnchor.sol). Key methods:

| Method | Purpose |
|---|---|
| `commitEpoch(bytes32 dagStateRoot, bytes calldata zkProof, uint64 epoch)` | Commit a new epoch. Anchors only accept monotonically increasing epoch numbers. |
| `getEpochRoot(uint64 epoch) view returns (bytes32)` | Lookup for off-chain dispute resolvers. |
| `verifyInclusion(uint64 epoch, bytes32 eventId, bytes32[] calldata proof) view returns (bool)` | Verify a Merkle path against an anchored root. |

Events:

| Event | Purpose |
|---|---|
| `EpochAnchored(uint64 indexed epoch, bytes32 root, bytes32 zkProofHash)` | Off-chain indexers, Patronus subscribers, and CAEP receivers all consume this. |

Errors:

| Error | Trigger |
|---|---|
| `EpochStale()` | Caller submitted a non-increasing epoch number. |
| `EpochAlreadyAnchored()` | Replay of a previously-anchored epoch. |
| `InvalidZkProof()` | Proof verification failed. |

## 5. Upgrade governance (Flaw 2)

The anchor contract is upgradeable, but **there is no developer admin key**. All upgrades route through `IKeychainUpgradeGovernor` — see [ADR-0002](adr/ADR-0002-web-of-trust-proxy-upgrade.md).

Summary:
- Any upgrade requires a 75% super-majority of staked HumanKey notaries with > 30 days of clean record.
- Timelock = 14 days for routine upgrades; 24h with 90% super-majority for emergency pauses.
- The genesis notary set comes from HumanKey's bonded federation bootstrap (P5; HumanKey ADR-0009).

## 6. Failure modes

| Failure | Mitigation |
|---|---|
| L2 reorg | Anchor contract re-accepts the new fork's canonical state; epochs are content-addressed, so the same `dagStateRoot` simply re-anchors. |
| L2 sequencer censorship | Anchor proposer submits to the L2's force-include / escape-hatch path; longer latency but liveness guaranteed by underlying Ethereum. |
| Malicious anchor proposer (submits wrong root) | ZK proof fails verification → revert. |
| Anchor proposer DoS | Proposer rotation per epoch via VRF (same VRF as the HumanKey notary tribunal selection). |
| Ethereum mainnet reorg deeper than L2 challenge period | Same as any L2 — extremely low probability; anchored state re-derives once Ethereum re-stabilizes. |

## 7. Open questions

- Anchor cadence: 1 minute vs 5 minutes — affects cost vs latency. Default: 1 minute, configurable.
- Multi-chain anchoring (anchor to Base AND Ethereum L1 directly for revocation events vs. anchor only to Base for routine events) — recommended as a v2 enhancement.

## 8. Acceptance criteria

1. The function signatures in [`IKeychainAnchor.sol`](../interfaces/contracts/IKeychainAnchor.sol) match §4 exactly.
2. The upgrade flow described in §5 matches [`IKeychainUpgradeGovernor.sol`](../interfaces/contracts/IKeychainUpgradeGovernor.sol) and [ADR-0002](adr/ADR-0002-web-of-trust-proxy-upgrade.md).
3. The anchor-rollup sequence in [`diagrams/04-anchor-rollup-sequence.mmd`](../diagrams/04-anchor-rollup-sequence.mmd) matches §3.
