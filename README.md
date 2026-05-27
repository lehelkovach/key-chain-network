# key-chain-network — Keychain Protocol

> A **Consent-Mediated Identity Bus** and **Dynamic Identity Firewall** — the decentralized cryptographic orchestration layer, ephemeral authorization system, and high-throughput event substrate that turns silent OAuth/token reuse into **Conspicuous Usage**.
>
> **Sister protocol:** [`lehelkovach/human-key-core`](https://github.com/lehelkovach/human-key-core) — Proof-of-Live-Human-Presence root-of-trust that sits on top of Keychain.

---

## Status

**Design pass — in review.** This repository is intentionally interfaces-only: design docs, ADRs, Solidity interface declarations (no function bodies), TypeScript declaration files (no runtime logic), and Mermaid diagrams. Implementation (Foundry, Rust BlockDAG node, ZK circuits, Patronus app shells, TEE oracle service) is **out of scope until this design is reviewed and accepted**.

The shared cross-repo contract files are stable and pinned by the sibling HumanKey repo:

- [`interfaces/contracts/events/IConspicuousUsageEvents.sol`](interfaces/contracts/events/IConspicuousUsageEvents.sol) — canonical event taxonomy
- [`interfaces/contracts/SharedStructs.sol`](interfaces/contracts/SharedStructs.sol) — cross-protocol Solidity structs
- [`interfaces/ts/shared-types.ts`](interfaces/ts/shared-types.ts) — TypeScript mirrors

---

## The thesis in one paragraph

Authentication today fails for one structural reason: the act of using an identity is invisible to its owner. A stolen session cookie, a replayed OAuth refresh token, a sub-agent silently inheriting its parent's scope, an AI agent's `~/.claude.json` exfiltrated by a malicious npm package — none of these surface to the user until damage is done. Keychain inverts this by making every identity action **conspicuous**: every session issuance, every delegated permission, every AI-agent action, every storage access generates an immutable cryptographic log that triggers a real-time alert to the user's sovereign devices. Throughput comes from a GHOSTDAG-style BlockDAG (Layer 1); finality comes from periodic Merkle commitments anchored on Ethereum L2 (Layer 2); data custody is encrypted and identity-bound (Layer 3); and a local AI guardian, **Patronus**, orchestrates consent, risk scoring, and short-lived ERC-4337 session keys on the user's hardware.

---

## The four layers

| # | Layer | Doc | Interface | Diagram |
|---|---|---|---|---|
| **L1** | BlockDAG (parallel event telemetry) | [`docs/01-layer1-blockdag.md`](docs/01-layer1-blockdag.md) | [`events/IConspicuousUsageEvents.sol`](interfaces/contracts/events/IConspicuousUsageEvents.sol) | [`02-container.mmd`](diagrams/02-container.mmd), [`03-conspicuous-usage-sequence.mmd`](diagrams/03-conspicuous-usage-sequence.mmd) |
| **L2** | Anchor (Base L2 Merkle commits) | [`docs/02-layer2-anchor.md`](docs/02-layer2-anchor.md) | [`IKeychainAnchor.sol`](interfaces/contracts/IKeychainAnchor.sol) | [`04-anchor-rollup-sequence.mmd`](diagrams/04-anchor-rollup-sequence.mmd) |
| **L3** | StorageNet (encrypted custody, log-before-serve) | [`docs/03-layer3-storagenet.md`](docs/03-layer3-storagenet.md) | [`IStorageNetGateway.sol`](interfaces/contracts/IStorageNetGateway.sol) | [`02-container.mmd`](diagrams/02-container.mmd) |
| **L4** | Patronus Guardian (local AI orchestrator) | [`docs/04-patronus-guardian.md`](docs/04-patronus-guardian.md) | [`ts/patronus-guardian.ts`](interfaces/ts/patronus-guardian.ts) | [`05-patronus-data-flow.mmd`](diagrams/05-patronus-data-flow.mmd), [`06-out-of-dom-consent.mmd`](diagrams/06-out-of-dom-consent.mmd) |

The defining principle that ties them together — [Conspicuous Usage](docs/05-conspicuous-usage.md).

---

## Defenses, mapped to current 2025–2026 threats

The protocol design is grounded in current authentication research (OWASP 2026, NIST SP 800-63B-4 Aug 2025, DEF CON 33 Aug 2025, Mitiga Apr 2026, CSA May 2026, MIT Tech Review Apr 2026, Trail of Bits Mar 2026, OpenZeppelin/Spearbit audits, IETF RFC 9901, OpenID CAEP 1.0).

The full STRIDE × Layer matrix and 33-class vulnerability catalog (V1–V33) lives in [`docs/07-threat-model.md`](docs/07-threat-model.md). Headlines:

| Threat | Keychain answer |
|---|---|
| **AiTM session theft** (Evilginx, Tycoon 2FA, Mamba 2FA) | Conspicuous Usage: stolen cookie alone authorizes nothing; signing emits `SessionUsed`; 24h dispute window |
| **AI agent OAuth token theft** (Mitiga `~/.claude.json` Apr 2026) | Ephemeral keys never persisted to disk — nothing to exfiltrate |
| **OAuth consent phishing** (CSA "EvilTokens" May 2026) | Every grant emits `DelegationGranted` — user sees it in seconds |
| **Sub-agent authority inheritance** (OpenID Foundation Oct 2025) | F3 consent transitivity: scope-monotonic sub-sessions, formally enforced |
| **WebAuthn API hijacking / prompt spoofing** (DEF CON 33 Aug 2025) | F1 out-of-DOM consent channel — page cannot render or proxy the dialog |
| **XSS passkey substitution** (Scott Helme, 2025–2026) | F1 plus Patronus owns the create-credential ceremony in its own process |
| **Synced passkey lacks attestation** | F2 hardware-backed authenticator required at Moderate+ tier (MDS3 / Secure Enclave attest) |
| **ERC-4337 session-key over-permissioning** (Trail of Bits Mar 2026) | F7 hardening ADR: decode inner calldata, denylist multicall/aggregate, sign gas fields, sign chain id, stateless validation |
| **Cross-context correlation** | Pairwise DIDs (ADR-0003): root DID never on-chain |
| **NIST SP 800-63B-4 AAL2/AAL3 phishing resistance** | `SessionPolicy.requiredAal` enforced on-chain |

---

## ADRs

| ADR | Topic | Addresses |
|---|---|---|
| [0001](docs/adr/ADR-0001-ephemeral-dag-pruning-zk-rollups.md) | Ephemeral DAG pruning with ZK rollups | Flaw 1 — DAG state bloat |
| [0002](docs/adr/ADR-0002-web-of-trust-proxy-upgrade.md) | Web-of-Trust proxy upgrade | Flaw 2 — admin key trap |
| [0003](docs/adr/ADR-0003-pairwise-dids-persona-abstraction.md) | Pairwise DIDs / persona abstraction | Flaw 3 — cross-context correlation (V23) |
| [0004](docs/adr/ADR-0004-l2-selection-base-vs-arbitrum.md) | L2 selection — Base | — |
| [0005](docs/adr/ADR-0005-event-fee-economic-model-sketch.md) | Event-fee economic model (sketch) | — |
| [0006](docs/adr/ADR-0006-out-of-dom-consent.md) | Out-of-DOM consent channel | F1; V4 / V5 |
| [0007](docs/adr/ADR-0007-erc4337-session-key-hardening.md) | ERC-4337 session-key hardening | F7; V24 / V25 / V26 / V27 |
| [0008](docs/adr/ADR-0008-caep-ssf-wire-format.md) | CAEP / SSF wire format | P1 |

---

## Quick map

```
.
├── docs/
│   ├── 00-overview.md              ◀ start here
│   ├── 01-layer1-blockdag.md
│   ├── 02-layer2-anchor.md
│   ├── 03-layer3-storagenet.md
│   ├── 04-patronus-guardian.md
│   ├── 05-conspicuous-usage.md
│   ├── 06-erc4337-ephemeral-keys.md
│   ├── 07-threat-model.md
│   ├── 08-glossary.md
│   ├── 09-consent-transitivity.md
│   └── adr/
│       └── ADR-0001 .. 0008
├── interfaces/
│   ├── contracts/
│   │   ├── events/IConspicuousUsageEvents.sol  ◀ SHARED with HumanKey
│   │   ├── SharedStructs.sol                   ◀ SHARED with HumanKey
│   │   ├── IKeychainAnchor.sol
│   │   ├── IKeychainUpgradeGovernor.sol
│   │   ├── IPairwiseDIDRegistry.sol
│   │   ├── IEphemeralSessionKeyManager.sol
│   │   ├── IStorageNetGateway.sol
│   │   └── README.md
│   └── ts/
│       ├── shared-types.ts                     ◀ SHARED with HumanKey
│       ├── patronus-guardian.ts
│       ├── dag-client.ts
│       ├── anchor-client.ts
│       ├── storagenet-client.ts
│       └── caep-emitter.ts
└── diagrams/
    └── *.mmd
```

---

## What is intentionally out of scope (v1 design pass)

- Tokenomics math beyond the qualitative sketch in [ADR-0005](docs/adr/ADR-0005-event-fee-economic-model-sketch.md).
- Production smart-contract implementations (this is interfaces-only).
- BlockDAG node software (recommended target: Rust, GHOSTDAG-derived).
- ZK circuits (recommended toolchain: Plonk over BN254 via circom 2.x baseline, Noir as portability option — final pick deferred to implementation pass).
- Patronus UI/UX, mobile or desktop app shells.
- TEE Oracle deployment automation.
- Legal / regulatory analysis beyond brief residency notes in HumanKey ADR-0006.
- Pivot P3 (Patronus browser extension) — deferred to v2.
- Pivot P4 (OIDC bridge / IdP mode) — deferred to v2.
- BBS+ interop on the ZK firewall — deferred to v2 (SD-JWT VC ships in v1 on the HumanKey side).

---

## License

MIT — see [LICENSE](LICENSE).

---

## How to review

1. Read [`docs/00-overview.md`](docs/00-overview.md).
2. Skim the four layer docs (01–04).
3. Read [`docs/05-conspicuous-usage.md`](docs/05-conspicuous-usage.md) — the defining principle.
4. Read [`docs/07-threat-model.md`](docs/07-threat-model.md) — see how V1–V33 each map to a mitigation.
5. Spot-check ADRs that interest you.
6. Spot-check the Solidity / TypeScript interfaces — NatSpec / JSDoc explains the design constraints inline.
7. Use the PR's checklist (`.github/pull_request_template.md`) to flag any concerns.
