# ADR-0005 — Event-Fee Economic Model (Sketch)

**Status:** Proposed (sketch — not finalized tokenomics)
**Date:** 2026-05-27
**Deciders:** Keychain protocol architecture

## Context

Layer 1 nodes need to be paid for including events. We need a fee model that:

- Discourages spam (each event costs something).
- Stays cheap enough that per-action logging is economically sane (sub-cent).
- Funds node operators sustainably (not VC-subsidy-dependent).
- Aligns with the HumanKey mint fee, which prepays 12 months of a new user's events.

This ADR is a **sketch**. Final tokenomics — supply curve, fee curve, validator rewards — are explicitly out of scope for the design pass and will be the subject of a separate tokenomics document.

## Decision (sketch)

1. DAG nodes are paid **per included event** from a prepaid user balance.
2. The user's balance is topped up via L2 bridge from any fungible token the protocol accepts (USDC and ETH at launch).
3. Pricing is set by a **fee market**: nodes name their minimum-acceptable per-event fee; clients submit to the cheapest node that meets latency/SLA needs. Protocol enforces a floor (anti-race-to-zero).
4. The **HumanKey mint fee** (set in HumanKey's economic friction model — $20–$50 per HumanKey ADR-0002 / docs/01) subsidizes the first **12 months** of the minted user's events. After 12 months, the user must top up.
5. The protocol takes a small protocol-treasury share (~10% of fees) routed to the upgrade governor contract for protocol-funded development bounties.

## Consequences

**Positive:**
- Spam-resistant: an attacker emitting events pays per event.
- New-user UX: 12 months of "free" events after mint, paid by the mint fee — removes onboarding friction.
- Sustainable node economics without inflation.

**Negative:**
- Heavy users pay more (which is the point, but needs clear UX warning).
- Fee market dynamics need tuning to prevent fee oscillation. Out of scope here; needs simulation.

## Alternatives considered

- **Free events, ad-supported** — rejected (silent surveillance is what the protocol exists to defeat).
- **Subscription model** — viable; defer to a separate tokenomics doc as one option.
- **Native token inflation funding nodes** — viable but introduces token-design complexity. Defer.

## Open questions

- Native token vs. accept any fungible (USDC, ETH). Recommend accept-any with USDC-denominated quoting.
- Fee floor amount. Recommend $0.0001 USD-equivalent per event.
- How HumanKey-inheritance handles fee-balance transfer to heirs. Defer to HumanKey inheritance design.

## References

- `docs/01-layer1-blockdag.md` §5
- HumanKey `docs/01-economic-friction-mint.md` (sister repo)
