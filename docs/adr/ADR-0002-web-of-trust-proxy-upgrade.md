# ADR-0002 — Web-of-Trust Proxy Upgrade

**Status:** Proposed
**Date:** 2026-05-27
**Deciders:** Keychain protocol architecture
**Addresses:** Handoff Flaw 2 — Admin Key Trap

## Context

Upgradeable smart contracts are standard practice on Ethereum and Layer 2s — and a standard attack surface. Every "admin key" that can change implementation is a centralized honeypot:

- A compromised developer key can steal user funds and rewrite protocol rules.
- A subpoenaed admin can be compelled to upgrade the contract for state actors.
- A multisig of N people is N people who can collude or be coerced.

Keychain holds the audit substrate for human identity. The upgrade admin must not be a single point of failure for the protocol's integrity.

## Decision

**No developer admin key. All proxy upgrades route through `IKeychainUpgradeGovernor` with a HumanKey-notary super-majority + timelock.**

Specifically:

1. Every upgradeable Keychain L2 contract has its proxy admin set to the `IKeychainUpgradeGovernor` contract.
2. To upgrade:
   - **Propose:** any address may submit `propose(proxy, newImpl, reason)` with a small bond (anti-spam).
   - **Vote:** active notaries (staked, > 30 days since stake, no slashes in the last 90 days) cast `vote(proposalId, support, sig)`.
   - **Execute:** after the timelock, if support ≥ super-majority threshold, `execute(proposalId)` runs the upgrade.
3. **Routine upgrade:** super-majority = 75%, timelock = 14 days.
4. **Emergency pause:** super-majority = 90%, timelock = 24 hours, executes only pause (not implementation change).
5. **Genesis notary set:** the HumanKey bonded federation per HumanKey ADR-0009 (P5) bootstraps the initial notary set; bonds decay over 24 months.

There is no escape hatch. There is no founder key. There is no "in case of emergency, dev team upgrades."

## Consequences

**Positive:**
- No single point of compromise.
- Coercion of a single individual cannot change the protocol.
- Upgrade history is auditable on-chain.
- Aligns governance with the protocol's own anti-Sybil substrate (notaries are vetted humans).

**Negative:**
- Notary collusion above 75% can still upgrade maliciously. This is a known trust limit; the bonded-federation bootstrap and 30-day clean-record requirement mitigate it but do not eliminate it.
- Genuine emergency response is delayed by the 24h floor. Acceptable cost; emergencies in Keychain are by design observable (Conspicuous Usage) so the 24h is a window to gather notary support, not to lose the protocol.
- Bootstrap problem: no notaries exist before HumanKey launches. Resolved by the P5 bonded federation: launch with a published federation set, decay bonds over 24 months.
- Upgrades become operationally complex; not a quick PR-and-deploy.

## Alternatives considered

- **2-of-3 multisig** — rejected (centralized; single state actor can subpoena 2 of 3).
- **Token-weighted governance** — rejected (whales dominate; HumanKey is one-person-one-vote by design).
- **Off-chain veto by a "guardian council"** — rejected (introduces another centralized failure mode).
- **Immutable contracts** — rejected (real bugs need real fixes; immutability is a luxury Keychain at this scope can't afford).

## Open questions

- Final super-majority threshold — 75% is recommended; could be 67% or 80%.
- Notary participation rates may be low; design includes a "minimum quorum" of 10% participation in addition to the super-majority of those who vote.
- Vote weight: 1 notary = 1 vote vs. stake-weighted. Recommend 1=1 for cultural alignment with HumanKey.

## References

- `docs/02-layer2-anchor.md` §5
- `interfaces/contracts/IKeychainUpgradeGovernor.sol`
- HumanKey ADR-0009 (bonded federation bootstrap, P5)
