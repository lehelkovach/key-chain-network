# ADR-0003 — Pairwise DIDs / Persona Abstraction

**Status:** Proposed
**Date:** 2026-05-27
**Deciders:** Keychain protocol architecture
**Addresses:** Handoff Flaw 3 — Cross-context correlation

## Context

A static, on-chain DID lets every relying party trivially correlate a user's actions across services. Platform collusion (e.g., joining datasets from two dApps a user interacts with) becomes a SQL join. This is V23 in the threat model.

Existing W3C DID Core supports pairwise DIDs in theory but most implementations publish a single root identifier and call it done. We need to enforce pairwise-by-default at the protocol level.

## Decision

**Every dApp-visible identity is a pairwise commitment derived per (rootDid, dappOrigin) via HKDF. The root DID never appears on-chain.**

Concretely:

1. The user's **root DID secret** lives in the device's secure enclave under Patronus's exclusive control.
2. For each `(rootDid, dappOrigin)` pair, Patronus derives a pairwise DID via:
   ```
   pairwiseSecret = HKDF(rootSecret, salt = "pairwise-did" || dappOrigin)
   pairwiseDid    = did:key derivation of pairwiseSecret
   pairwiseCommitment = keccak256(pairwiseDid.publicKey)
   ```
3. All on-chain artifacts — DAG events, session keys, anchor commits — use only the `pairwiseCommitment`.
4. All dApp-facing artifacts — passkey assertions, signature payloads, DPoP proofs — use only the pairwise DID, never the root.
5. The `IPairwiseDIDRegistry` contract holds *commitments only*. There is no on-chain mapping from commitment back to root. This is by design and not negotiable.

## Consequences

**Positive:**
- Cross-context correlation requires breaking HKDF. This is the same security level as the underlying root secret.
- One dApp's compromise does not compromise others — the leak is scoped to one pairwise persona.
- Aligns with W3C DID Core "pairwise DID" guidance, takes it from "supported" to "enforced".

**Negative:**
- Users who want a unified view across personas need Patronus to provide it client-side; this is a real UX problem to solve in the Patronus app.
- Recovery has to roll *every* pairwise persona atomically; complicates the recovery state machine (handled in HumanKey lineage recovery).
- Inter-dApp interactions ("send these tokens to my friend Alice on dApp Y") require explicit user mediation; you cannot just "introduce one dApp to another" without re-deriving.
- The `dappOrigin` definition matters: include subdomains? port? path? Decision: scheme + host + port; path and query do not participate. Defined in `interfaces/contracts/IPairwiseDIDRegistry.sol`.

## Alternatives considered

- **Static DID per user** — rejected (the entire problem statement).
- **Pairwise opt-in** — rejected (defaults dominate; opt-in privacy is the privacy that isn't there).
- **Server-derived pairwise** (issuer mints the pairwise) — rejected (centralized; defeats the trust model).
- **BBS+ unlinkable proofs only** (no pairwise DIDs needed) — considered; complementary, not alternative. BBS+ for *credential* unlinkability; pairwise DIDs for *session* unlinkability. P2 in HumanKey covers BBS+ in v2.

## Open questions

- HKDF salt fixing — should `salt` include a protocol version byte for future migration? Recommend yes; defer concrete format.
- Cross-device synchronization of pairwise derivation (so the user's phone and desktop derive the same pairwise for the same origin) — solved by deriving from the same root, but requires careful root-secret sync via HumanKey lineage. Documented in `04-patronus-guardian.md` open questions.
- Whether to support user-chosen named personas ("anonymous", "professional", "casual") on top of automatic per-origin derivation — defer to v2.

## References

- `docs/00-overview.md` §5
- `docs/06-erc4337-ephemeral-keys.md` §4
- `interfaces/contracts/IPairwiseDIDRegistry.sol`
- W3C DID Core Recommendation
- RFC 5869 — HKDF
