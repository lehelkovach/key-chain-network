# ADR-0001 — Ephemeral DAG Pruning with ZK Rollups

**Status:** Proposed
**Date:** 2026-05-27
**Deciders:** Keychain protocol architecture
**Addresses:** Handoff Flaw 1 — DAG state bloat

## Context

The Conspicuous Usage principle requires that every identity action emits a Layer 1 event. At realistic adoption (millions of users, AI agents acting at machine speed) this is hundreds of millions of events per day. Retaining all of them globally and forever bloats DAG active state to a point where running a node becomes impractical, defeating decentralization.

Three obvious-but-bad alternatives:
1. **Retain forever.** Bloat is unbounded; node count drops; centralization wins.
2. **Hard-delete after N days.** Audit history is destroyed; the protocol becomes its own attacker.
3. **Log only to L2.** Gas cost makes per-action logging economically infeasible.

## Decision

**Ephemeral DAG pruning, backed by ZK rollup proofs anchored on L2.**

1. Granular L1 events stay in active DAG state for **30 days** (configurable; floor 7 days).
2. At each pruning epoch boundary, a designated set of prover nodes runs a recursive ZK proof that takes the past 30 days of events as private input and produces:
   - a public commitment (Merkle accumulator root over event IDs), and
   - a proof that the accumulation is correct.
3. The proof + commitment is anchored on Layer 2 via `IKeychainAnchor.commitEpoch`. (Operationally this is the same anchoring mechanism that runs every regular epoch; the pruning epoch is one of the regular epochs.)
4. After successful anchor, DAG nodes drop the granular events from active state.
5. Users retain their own copies of relevant events in their personal StorageNet (Layer 3). Re-proving any single historical event's existence is `Merkle path + anchored commitment` — verifiable forever.

## Consequences

**Positive:**
- Bounded active DAG state regardless of total event count.
- Cryptographic guarantee that no event was silently deleted; users can always re-prove their own history.
- Decentralization preserved (running a node has bounded resource requirements).
- Same prover infrastructure serves both regular epoch anchoring and pruning anchoring.

**Negative:**
- Nodes need ZK prover capacity. Recommend plonky2 for recursion speed (final pick deferred).
- A user who loses both their StorageNet copies *and* the granular event window cannot re-prove individual events (they only have the commitment).
- Adds a "pruning epoch" complexity: the architecture must distinguish "regular event anchoring" from "pruning anchoring" in operational tooling.

## Alternatives considered

- **Forever retention** — rejected (bloat).
- **Hard delete with no proof** — rejected (audit destroyed).
- **L2-only logging** — rejected (gas cost).
- **30-day commitment to L1 only (no L2 anchor)** — rejected; without L2 anchor, the commitment is no harder to forge than the DAG itself.
- **Halo2 vs plonky2 vs Nova** — defer ZK prover choice; design assumes recursive STARK family.

## Open questions

- Final ZK prover (plonky2 recommended; not locked).
- Per-user opt-in for longer retention windows (e.g., regulated industries with 7-year audit needs) — defer.
- Whether to anchor pruning proofs additionally to Ethereum L1 directly for stronger inheritance against L2 reorgs — see [ADR-0004](ADR-0004-l2-selection-base-vs-arbitrum.md) open questions.

## References

- `docs/01-layer1-blockdag.md` §6
- `docs/02-layer2-anchor.md` §3
- GHOSTDAG paper (Kaspa, 2018) — substrate.
- Polygon Zero "Plonky2" — recursive proof system reference.
