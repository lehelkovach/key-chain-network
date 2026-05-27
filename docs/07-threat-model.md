# Threat Model

> Grounded in current (2025–2026) authentication and identity research.

## 1. Methodology

This threat model is **STRIDE × Layer**, plus a vulnerability-class catalog (V1–V33) drawn from the 2025–2026 literature.

- **STRIDE** — Spoofing, Tampering, Repudiation, Information disclosure, Denial of Service, Elevation of privilege.
- **Layers** — L1 BlockDAG, L2 Anchor, L3 StorageNet, L4 Patronus Guardian, and the cross-cutting ERC-4337 surface.

Each STRIDE cell must point to a mitigation (doc, ADR, or interface clause). No cell is empty.

## 2. Attacker profiles

| Profile | Capabilities | Example |
|---|---|---|
| **Curious dApp** | Can observe user actions against itself; cannot break crypto. | A platform trying to fingerprint or cross-correlate users. |
| **Malicious dApp** | Curious dApp + actively tries to escalate scope / phish consent. | A typosquat dApp serving a spoofed UI. |
| **Compromised user device** | Root on the user's machine; can read browser memory, env vars, config files. | Mitiga's `~/.claude.json` exfiltration (V10). |
| **Compromised relay / sequencer** | Can censor or delay messages but cannot forge signatures. | Hostile L2 sequencer (V9). |
| **AiTM phishing kit operator** | Runs Evilginx 3 / Tycoon 2FA / Rockstar 2FA / Mamba 2FA. | Captures session cookies after MFA (V1). |
| **Compromised notary** | Holds notary stake; can sign attestations falsely until slashed. | HumanKey tribunal coercion. |
| **Compromised TEE flavor** | A published vulnerability in Nitro / TDX / SEV-SNP. | Triggers F9 deprecation flow. |
| **Sub-agent inheritance attacker** | Convinces an AI agent to spawn a sub-agent inheriting its scope. | OpenID Foundation Oct 2025 paper (V13). |
| **Prompt-injection attacker** | Convinces an LLM to emit credentials in tool-call outputs (V14). | Indirect prompt injection through web content. |
| **Deepfake puppet operator** | Real human behind a real-time face-swap mask. | Defeats challenge-response liveness; CEO Doppelgänger (V18). |
| **State-level adversary** | Subpoena, coerce, or compel any centralized component. | Why no honeypots; biometrics never leave device/TEE (V22). |

## 3. Vulnerability-class catalog (V1–V33)

Curated from OWASP Top 10 2026 / A07, NIST SP 800-63B-4 (Aug 2025), DEF CON 33 (Aug 2025), Scott Helme 2025–2026, Mitiga Labs Apr 2026, CSA May 2026, MIT Tech Review Apr 2026, Trail of Bits Mar 2026, OpenZeppelin/Spearbit, IETF RFC 9901, W3C BBS+, OpenID CAEP 1.0.

| ID | Class | Status | Mitigation pointer |
|---|---|---|---|
| V1 | AiTM session theft | COVERED | `05-conspicuous-usage.md` §2 |
| V2 | OAuth/OIDC implementation flaws | COVERED (by removal) | Pairwise DIDs replace OAuth for native integrations |
| V3 | Credential stuffing / hybrid password | COVERED (by removal) | No passwords |
| V4 | WebAuthn API hijacking (prompt spoofing) | COVERED | F1 + [ADR-0006](adr/ADR-0006-out-of-dom-consent.md) |
| V5 | XSS-driven passkey substitution | COVERED | F1 + ADR-0006 |
| V6 | WebAuthn logic flaws | N/A directly | Patronus owns its own ceremony; lessons applied in `04-patronus-guardian.md` |
| V7 | Recovery as attack surface | COVERED | HumanKey lineage recovery; NO SMS/email anywhere |
| V8 | Synced passkey lacks attestation | COVERED | F2 in `06-erc4337-ephemeral-keys.md` §5 |
| V9 | Post-auth session theft (general) | COVERED | Conspicuous Usage + CAEP (P1, ADR-0008) |
| V10 | AI agent OAuth token theft (Mitiga) | COVERED | Ephemeral keys never persisted; F4 LLM isolation |
| V11 | OAuth consent phishing (EvilTokens) | COVERED | Every grant is conspicuous |
| V12 | AI SaaS supply-chain blast radius | COVERED | Pairwise DIDs + per-session policies + revocation |
| V13 | Sub-agent authority inheritance | COVERED | F3 in `09-consent-transitivity.md` |
| V14 | Prompt-injection credential exfiltration | COVERED | F4 in `04-patronus-guardian.md` §5 |
| V15 | Over-scoped tokens | COVERED | `SessionPolicy` `allowedSelectors`/`maxValueWei`/`policyHash` |
| V16 | Missing sender-constrained tokens | COVERED | Session key IS the constraint; DPoP profile in `06-erc4337` §9 |
| V17 | Biometric injection (VCam / hooking) | COVERED (HumanKey) | HumanKey F5 device attestation |
| V18 | Real-time deepfake puppet | COVERED (HumanKey) | HumanKey Adaptive Escalation High tier + TEE Oracle |
| V19 | Voice cloning / TD-VIM | COVERED (HumanKey) | HumanKey F6 voice-never-alone |
| V20 | 3D mask attacks | COVERED (HumanKey) | Flash-test + cognitive prompts + multi-signal PAD |
| V21 | Sybil attacks | COVERED (HumanKey) | HumanKey core thesis |
| V22 | KYC honeypots | COVERED | Biometrics never leave device/TEE; commitments only |
| V23 | Cross-context correlation | COVERED | Pairwise DIDs ([ADR-0003](adr/ADR-0003-pairwise-dids-persona-abstraction.md)) |
| V24 | 4337 multicall escape | COVERED | F7 / [ADR-0007](adr/ADR-0007-erc4337-session-key-hardening.md) |
| V25 | 4337 sig validation gaps (gas fields) | COVERED | F7 / ADR-0007 |
| V26 | 4337 cross-chain replay | COVERED | F7 / ADR-0007 |
| V27 | 4337 state-modify during validate | COVERED | F7 / ADR-0007 |
| V28 | Dormant OAuth grants | COVERED | F8 periodic session audit in `04-patronus-guardian.md` |
| V29 | Inheritance / dead-account lockout | COVERED (HumanKey) | HumanKey ADR-0003 Patronus-driven time-lock |
| V30 | Identical twin collision | COVERED (HumanKey) | HumanKey ADR-0004 multimodal entropy |
| V31 | Liveness injection mid-pipeline | COVERED (HumanKey) | TEE Oracle + F5 device attestation |
| V32 | TEE compromise | COVERED (HumanKey) | HumanKey F9 / ADR-0007 deprecation policy |
| V33 | NIST AAL2/AAL3 phishing resistance | COVERED | `SessionPolicy.requiredAal` + `00-overview.md` §6 |

## 4. STRIDE × Layer matrix

### L1 — BlockDAG

| | Threat example | Mitigation |
|---|---|---|
| **S**poof | Forged event from unknown actor | Events signed by ephemeral session key bound to pairwise DID; pairwise commitment in event payload |
| **T**amper | Replay or rewrite of historical events | Anchored Merkle root on L2 + ZK pruning proof ([ADR-0001](adr/ADR-0001-ephemeral-dag-pruning-zk-rollups.md)) |
| **R**epudiate | User denies an action they performed | Signed event + 24h dispute window; non-repudiation post-window |
| **I**nfo disclosure | Node operator reads event payload | `payloadHash` on chain only; full body in encrypted StorageNet |
| **D**oS | Node refuses to include event | Non-exclusive submission; user submits to any node |
| **E**oP | Node injects false events | Node stake slashed; event signature must verify against session key |

### L2 — Anchor

| | Threat | Mitigation |
|---|---|---|
| **S** | Forged anchor commit | ZK proof gates `commitEpoch` |
| **T** | Re-anchor of different root for same epoch | Epoch numbers monotonic + `EpochAlreadyAnchored` error |
| **R** | Anchor proposer denies submission | On-chain `EpochAnchored` event is the receipt |
| **I** | L2 sequencer infers user identity from anchor pattern | Anchors are aggregate Merkle roots; per-user info not leaked |
| **D** | L2 sequencer censors anchor calls | L2 force-include / escape-hatch path |
| **E** | Admin upgrades to malicious impl | [ADR-0002](adr/ADR-0002-web-of-trust-proxy-upgrade.md) 75% notary super-majority + 14d timelock |

### L3 — StorageNet

| | Threat | Mitigation |
|---|---|---|
| **S** | Unauthorized reader requests data | `authProof` required; ZK proof or sig over `pairwiseCommitment` |
| **T** | Storage node corrupts object | Content-addressed; client verifies hash |
| **R** | Node denies access ever happened | `AccessLogged` event emitted before serve; cryptographically attributable |
| **I** | Node reads object bytes | XChaCha20-Poly1305; node sees ciphertext only |
| **D** | Node refuses to serve | Multi-node replication; client retries |
| **E** | Revoked reader retains pre-revocation copy | Acknowledged limit; key rotation invalidates future access |

### L4 — Patronus

| | Threat | Mitigation |
|---|---|---|
| **S** | Malicious app impersonates Patronus consent UI | F1 out-of-DOM channel ([ADR-0006](adr/ADR-0006-out-of-dom-consent.md)) |
| **T** | Tampered Patronus binary | Platform code signing + Patronus self-attestation in DAG events |
| **R** | User denies they consented | Consent event signed by hardware-backed authenticator |
| **I** | Patronus leaks root secret to LLM | F4 — interface contract has no `getKey()` method |
| **D** | dApp DoSes consent UX with prompts | Patronus rate-limits per pairwise DID |
| **E** | dApp escalates Low tier to admin scope | Risk evaluator + F3 consent transitivity bound |

### ERC-4337 surface

| | Threat | Mitigation |
|---|---|---|
| **S** | Forged session-key signature | secp256k1 keypair; validated by `validateUserOp` |
| **T** | Calldata mutation post-sign (V24 multicall escape) | F7 — inner-calldata decode, denylist forwarders |
| **R** | UserOp executed but no log | DAG `SessionUsed` event; impossible to execute without |
| **I** | Session key disclosed | Never persisted to disk; derived in enclave on use |
| **D** | Bundler griefs validator | Stateless validation per F7 |
| **E** | Cross-chain replay (V26) | chain id in signed hash per F7 |

## 5. Open issues tracked

- **OQ-T1** Quantum-resilience for session keys — pre-quantum secp256k1 today; ed25519-dilithium hybrid is a v2 candidate.
- **OQ-T2** Notary collusion above the 75% threshold — beyond the design's trust model; deserves a published incident-response runbook in v2.
- **OQ-T3** Side-channel attack on Patronus device — outside protocol scope; rely on device vendor attestation.

## 6. Acceptance criteria

1. Every vulnerability class in §3 has a mitigation pointer (no "TBD").
2. Every STRIDE × Layer cell in §4 has a mitigation pointer (no empty cells).
3. The doc references current (2025–2026) literature for each cited threat class.
