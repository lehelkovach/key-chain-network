# ADR-0004 — L2 Selection: Base vs. Arbitrum

**Status:** Proposed
**Date:** 2026-05-27
**Deciders:** Keychain protocol architecture

## Context

The Anchor Layer (Layer 2) is the bridge from Keychain's high-throughput Layer 1 to Ethereum-grade economic security. The choice of L2 affects:

- Per-byte anchor cost (we anchor frequently — every ~1 minute).
- Withdrawal / challenge period (relevant for time-sensitive flows like revocation).
- Ecosystem reach (HumanKey sponsorship onramps depend on L2 user base).
- Sequencer trust model.
- Long-term roadmap risk.

The realistic candidates as of mid-2026 are Base, Arbitrum One, Optimism, and zk-rollups (Linea, Scroll, zkSync).

## Decision

**Pick Base for v1. Write all contracts to be portable so re-deployment to Arbitrum / Optimism / a zk-rollup is a deployment-script change, not a contract rewrite.**

Reasons for Base over the alternatives:

| Criterion | Base | Arbitrum | Optimism | zk-rollup |
|---|---|---|---|---|
| EIP-4844 blob calldata cost | Lowest in practice (early adopter) | Comparable | Comparable | Comparable or better |
| Sequencer model | Coinbase-operated; decentralization roadmap | Offchain Labs; decentralizing | Optimism Foundation | Varies (more centralized today) |
| Ecosystem reach for sponsorship onramps (P5) | **Strong** (Coinbase user base, Smart Wallet) | Moderate | Moderate | Smaller, growing |
| Withdrawal period | 7 days (optimistic) | 7 days (optimistic) | 7 days (optimistic) | ~1 hour (zk) |
| Account abstraction native support | ERC-4337 supported | ERC-4337 supported | ERC-4337 supported | Varies; some have native AA |
| Maturity (audit history) | High | Highest | High | Mixed |

The 7-day optimistic withdrawal period is acceptable because revocation is enforced **off-chain** via the CAEP wire format (which propagates immediately) and **on-chain** via the revocation bitmap, which does not require an L2 → L1 withdrawal.

## Consequences

**Positive:**
- Lowest realistic per-anchor cost in v1.
- Best Web3 onramp story via Coinbase for the HumanKey sponsorship protocol.
- Mature, well-audited L2.
- Contracts written to portable interfaces; if Base disappoints, redeploy is cheap.

**Negative:**
- Coinbase sequencer is a single point of liveness failure (mitigated by force-include / escape-hatch path, which we depend on for censorship resistance).
- Optimistic 7-day finality means revocation events take 7 days to be enforceable at the L1 settlement level. Not a real issue given how revocation actually works (off-chain CAEP + on-chain bitmap), but worth flagging.

## Alternatives considered

- **Arbitrum One** — strong second choice; equally portable. Decision would flip if Base's sequencer roadmap stalls or if Stylus changes the cost picture materially.
- **Optimism** — viable; smaller ecosystem reach for sponsorship onramps.
- **zk-rollup (Linea/Scroll/zkSync)** — better finality story; smaller ecosystem; younger code. Recommended as a **secondary anchor target** in v2 for revocation-class events specifically (anchor revocations to a zk-rollup; anchor routine events to Base). This is a v2 enhancement, flagged in `02-layer2-anchor.md` §7.
- **Ethereum L1 directly** — rejected (gas cost makes per-minute anchoring economically infeasible).

## Open questions

- Two-target anchoring (Base for routine, zk-rollup for revocation) — recommend v2.
- Whether to use Base's "Base Account" Smart Wallet primitives for the sponsorship UX directly — recommend yes; defer to implementation pass.

## References

- `docs/02-layer2-anchor.md` §2
- Base docs — blob calldata cost, sequencer roadmap.
- EIP-4844 (blob transactions).
