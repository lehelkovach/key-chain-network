# Layer 1 — The Keychain BlockDAG (Execution & Telemetry)

> The substrate of Conspicuous Usage. Optimized for *event data*, not currency UTXOs.

## 1. Why a DAG, not a chain

A linear blockchain serializes all blocks in time. That cap on parallelism is acceptable when blocks carry low-frequency, high-value financial state, but it is fatal when blocks carry **identity telemetry** — every session issuance, every delegated action, every storage access. The Keychain BlockDAG draws from GHOSTDAG (Kaspa) to allow many parallel blocks per "epoch", ordered after the fact via the K-cluster heuristic. The net effect: high inclusion throughput, sub-second time to first inclusion, sub-cent cost per event.

We do **not** re-derive GHOSTDAG here; treat it as a designed-in primitive and consult the Kaspa whitepaper for the consensus details. What is in scope for this doc is the *application layer* on top of that DAG.

## 2. The block

A Keychain L1 block is a small, signed envelope:

```
Block {
    version:      uint8,
    parents:      Hash[2..K],   // K-tip selection per GHOSTDAG
    nodeId:       Hash,         // proposing node
    timestamp:    uint64,
    events:       Event[1..N],  // see §3
    sig:          BLS / Ed25519,
    epoch:        uint64,       // for anchor coordination, see Layer 2
}
```

Blocks reference parents; the DAG is the union of all blocks; ordering is finalized retroactively per GHOSTDAG.

## 3. The event

Every event carried in the DAG conforms to a single envelope:

```
Event {
    eventId:            Hash,             // unique per event
    eventType:          bytes32,          // canonical taxonomy, §4
    subjectPairwise:    PairwiseCommitment,
    actorPubKey:        Hash,             // ephemeral session key or notary key
    payloadHash:        Hash,             // commits to off-chain detail
    timestamp:          uint64,
    nonce:              uint64,           // per pairwise commitment
    nodeSig:            Signature,        // node that first ingested
}
```

The `payloadHash` lets Patronus and dispute resolvers fetch the full off-chain detail from StorageNet (Layer 3) while the on-chain footprint stays tiny.

## 4. Event taxonomy (canonical)

The full taxonomy is the source of truth in [`interfaces/contracts/events/IConspicuousUsageEvents.sol`](../interfaces/contracts/events/IConspicuousUsageEvents.sol). Summary:

| `eventType` | Emitter | When |
|---|---|---|
| `SessionIssued` | Keychain (ERC-4337 manager) | New ephemeral session key installed for a pairwise DID |
| `SessionUsed` | Keychain | Session key signed a UserOp / action |
| `SessionRevoked` | Keychain | Session terminated (user / expiry / anomaly) |
| `SessionReused` | Keychain | Replay of a previously-used session detected (V1 AiTM trip) |
| `DelegationGranted` | Keychain | User → agent or agent → sub-agent delegation (F3 enforces scope ⊆ parent scope) |
| `AgentAction` | Keychain | AI agent or any delegated identity took an action |
| `StorageAccess` | Layer 3 gateway | Read / write / delete / key-rotate (emitted **before** data plane responds) |
| `AnomalyDetected` | Patronus / DAG nodes | Any of: failed High-tier authn, atypical geo, cookie replay, sub-agent scope escalation |
| `NotaryAttestation` | HumanKey | One of three notaries signed off on a pending mint or recovery |
| `Minted` | HumanKey | zkNFT minted (with optional sponsor address per P5) |
| `RecoveryInitiated` | HumanKey | Burn-and-rebind started; delay window begins |
| `LineageRebound` | HumanKey | Recovery finalized; new zkNFT references old as lineage anchor |
| `InheritanceTick` | HumanKey | State machine tick (Alive/Stale/Grace/Claimable/Claimed/Cancelled) |

## 5. Throughput and cost targets (qualitative)

- **Latency to first inclusion** — target < 2 s. The Patronus alert SLA depends on this.
- **Cost per event** — target < $0.001 worth of native fee token, paid from a prepaid user balance topped up via L2 bridge.
- **Dispute window** — 24 h by default, user-configurable; hard floor 1 h.
- **Telemetry retention** — granular events kept 30 days (see §6 pruning), permanent commitment via the anchor layer.

These are design targets, not measured numbers. Once the Rust client lands, this section will be replaced with benchmarks.

## 6. Ephemeral DAG pruning (Flaw 1)

See [ADR-0001](adr/ADR-0001-ephemeral-dag-pruning-zk-rollups.md).

Granular event history would bloat the global DAG state if kept forever. Instead:

1. Granular events live in active DAG state for 30 days.
2. At each pruning epoch boundary, a designated set of nodes runs a ZK prover (target: plonky2 for fast recursion) that takes the past 30 days of events as private input and produces a public commitment + proof of correct summarization.
3. The proof and commitment anchor onto Layer 2 (see [`02-layer2-anchor.md`](02-layer2-anchor.md)).
4. The raw events are then dropped from active state. Users still hold their own copies on StorageNet (Layer 3) and can re-prove any single event's inclusion via Merkle path + the anchored commitment.

This buys the property "the DAG is cheap enough to log everything, but globally bounded in active size."

## 7. Failure modes

| Failure | Mitigation |
|---|---|
| Equivocating node (publishes conflicting events) | Node stake slashed; GHOSTDAG K-cluster ordering tolerates honest reorders |
| Censoring node (refuses an event) | User submits to any other node; events are non-exclusive |
| DAG fork | GHOSTDAG resolves; anchor layer ratifies the eventually-included set |
| Anchor griefing (Layer 2 sequencer ignores commits) | See [`02-layer2-anchor.md`](02-layer2-anchor.md) §failure modes |
| ZK prover unavailable at epoch boundary | Pruning is delayed; granular state grows; alert raised; no correctness impact |

## 8. Open questions

- Final choice of recursive ZK prover for §6 — plonky2 vs Halo2.
- Fee market design for event inclusion (sketched in [ADR-0005](adr/ADR-0005-event-fee-economic-model-sketch.md), not finalized).
- Rust-vs-Go for the reference node implementation (out of scope; design assumes Rust).

## 9. Acceptance criteria for this doc

1. Every event ever emitted by Keychain or HumanKey appears in the taxonomy table (§4) and in the canonical Solidity interface.
2. The block / event schemas (§2, §3) match the field orderings expected by downstream serializers.
3. The pruning approach (§6) is consistent with [ADR-0001](adr/ADR-0001-ephemeral-dag-pruning-zk-rollups.md).
