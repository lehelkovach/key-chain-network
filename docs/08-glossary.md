# Glossary

Terms used across the Keychain Protocol design documents.

| Term | Definition |
|---|---|
| **AAL** | Authenticator Assurance Level. NIST SP 800-63B-4 (Aug 2025) defines AAL1, AAL2, AAL3. Mapped to Keychain risk tiers in `00-overview.md` §6. |
| **AiTM** | Adversary-in-the-Middle. Phishing technique that proxies the legitimate site to steal the post-MFA session cookie. See V1 in `07-threat-model.md`. |
| **Anchor (Layer 2)** | The Ethereum L2 (Base in v1) where Keychain commits epoch Merkle roots for final settlement. |
| **BlockDAG** | The Layer 1 substrate; a directed acyclic graph of signed event-bearing blocks, ordered via GHOSTDAG. |
| **CAEP** | OpenID Continuous Access Evaluation Profile 1.0. Standard wire format for the conspicuous events. See P1, [ADR-0008](adr/ADR-0008-caep-ssf-wire-format.md). |
| **Cognitive MFA** | Randomized challenge-response prompts issued by Patronus and verified by the Confidential TEE Oracle. Defeats deepfake puppets that can only mimic biometrics, not reasoning. |
| **Conspicuous Usage** | The defining principle: no identity action is silent. See `05-conspicuous-usage.md`. |
| **Confidential TEE Oracle** | The HumanKey component that processes high-risk liveness video in a secure enclave (Nitro/TDX/SEV-SNP) and emits a signed `LivenessAttestation`. Video is purged before the attestation returns. |
| **Consent Transitivity** | F3 — formal rule that any sub-session derived from a parent session must have scope ⊆ parent scope. See `09-consent-transitivity.md`. |
| **DAG** | Directed Acyclic Graph. The Layer 1 structure. |
| **dApp** | Decentralized application; any external party interacting with the user via Keychain. |
| **Dispute Window** | 24h-by-default user-configurable interval after a conspicuous event during which the user can revoke. Hard floor 1h. |
| **DID** | Decentralized Identifier (W3C DID Core). Pairwise DIDs are derived per (rootDid, dappOrigin). |
| **DPoP** | Demonstration of Proof-of-Possession (RFC 9449). Keychain session keys are DPoP-compatible by construction. See `06-erc4337-ephemeral-keys.md` §9. |
| **Ephemeral Session Key** | A short-lived, scope-bounded ERC-4337 session keypair, HKDF-derived per session and never persisted. |
| **F1–F9** | The nine features added to the protocol after the 2026-05 research pass. See `00-overview.md` §7 traceability matrix. |
| **GHOSTDAG** | Greedy Heaviest Observed Sub-Tree DAG. The consensus algorithm Keychain's L1 is inspired by (originally Kaspa). |
| **HKDF** | HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869). Used to derive pairwise DIDs and session keys. |
| **HumanKey** | The sister protocol providing Proof-of-Live-Human-Presence as Keychain's root-of-trust. See `lehelkovach/human-key-core`. |
| **Lineage Anchor** | A non-transferable NFT that preserves a HumanKey's audit history after burn-and-rebind recovery. |
| **MDS3** | FIDO Metadata Service v3. Database of authenticator characteristics; Patronus uses it to verify hardware-backing per F2. |
| **Notary** | A HumanKey participant who stakes and signs attestations during tribunal (mint) and recovery flows. |
| **OOD** | Out-of-DOM. The consent channel Patronus uses; defeats DEF CON 33 prompt spoofing and Scott Helme's XSS passkey hijacking. See F1, [ADR-0006](adr/ADR-0006-out-of-dom-consent.md). |
| **Pairwise DID** | A per-(rootDid, dappOrigin) DID derived via HKDF. Defeats cross-context correlation. See [ADR-0003](adr/ADR-0003-pairwise-dids-persona-abstraction.md). |
| **Patronus Guardian** | The user's local AI orchestrator. See `04-patronus-guardian.md`. |
| **PoP** | Proof of Personhood. The Sybil-resistance class HumanKey occupies. |
| **Pruning Epoch** | The 30-day cadence at which L1 raw events are summarized into a ZK proof and dropped from active state. See [ADR-0001](adr/ADR-0001-ephemeral-dag-pruning-zk-rollups.md). |
| **Revocation, Limits Of** | Symmetric crypto fact: a reader who has decrypted bytes once cannot be made to forget them. Revocation prevents *future* access only. |
| **Risk Tier** | Low / Moderate / High in the Adaptive Escalation matrix. Drives authenticator requirements per F2 and the TEE-Oracle invocation per HumanKey ADR-0001. |
| **SessionPolicy** | Off-chain struct whose hash is committed on-chain in `SessionIssued`. Field order is part of the shared cross-repo contract (`SharedStructs.sol`). |
| **SET** | Security Event Token (RFC 8417). The signed-JWT envelope CAEP uses for transport. |
| **Shared Cross-Repo Contract** | The three files in `interfaces/contracts/events/IConspicuousUsageEvents.sol`, `interfaces/contracts/SharedStructs.sol`, and `interfaces/ts/shared-types.ts` that are pinned by both repos. Must not be modified without coordination. |
| **SSF** | Shared Signals Framework. The OpenID standard CAEP profiles. |
| **StorageNet** | Layer 3; encrypted decentralized custody of identity-bound data. |
| **TEE** | Trusted Execution Environment. AWS Nitro, Intel TDX, AMD SEV-SNP. |
| **Tribunal** | The 3-of-3 randomly-selected staked notaries who verify a HumanKey mint via live video. 2-of-3 for recovery. |
| **VRF** | Verifiable Random Function. Used to select notary tribunals (Chainlink VRF in v1). |
| **Web-of-Trust Proxy Upgrade** | F1's L2 upgrade pattern: 75% notary super-majority + 14d timelock; no developer admin key. See [ADR-0002](adr/ADR-0002-web-of-trust-proxy-upgrade.md). |
| **WebAuthn / FIDO2** | The browser-side passkey API. Keychain doesn't use it directly but Patronus implements equivalent guarantees (origin binding, hardware attestation). |
| **zkNFT** | The non-transferable token a HumanKey mint produces. |
