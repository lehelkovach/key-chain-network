# ERC-4337 Ephemeral Session Keys

> Short-lived, scope-bounded, never persisted. The post-AiTM signing primitive.

## 1. Why ephemeral session keys

A long-lived signing key is a long-lived liability. If the device that holds it is compromised, every future signature is forged.

Ephemeral session keys flip the model:

- **Per-session keypair**, HKDF-derived on demand from the pairwise-DID root.
- **Scope-bounded** — restricted to specific function selectors, value caps, expiries, geofences, NIST AAL minimums.
- **Never persisted to disk** — derived in Patronus's enclave on use; existence ends when the policy expires.
- **Revocable** — one DAG event + one bitmap flip on-chain.

If the device is compromised, the attacker steals nothing useful: there is no key file to copy, and any forged signature is publicly logged and revocable within the dispute window.

## 2. The lifecycle

```
1. dApp requests a session for purpose P with scope S.
2. Patronus evaluates risk (Low / Moderate / High per adaptive escalation).
3. F1 — out-of-DOM consent prompt; user approves with the appropriate authenticator
        (Low: passkey; Moderate: hardware-backed + biometric + device attestation;
        High: + TEE liveness + cognitive MFA).
4. F2 — Patronus verifies the authenticator's hardware-backing via FIDO MDS3
        (or equivalent) for Moderate+ tiers.
5. Patronus HKDFs an ephemeral keypair under the pairwise DID for (dappOrigin, scope, expiry).
6. Patronus installs the session via IEphemeralSessionKeyManager.installSessionKey(...)
   with a SessionPolicy whose `policyHash` is committed on-chain in SessionIssued.
7. Each UserOp signed under the session emits SessionUsed.
8. On expiry / user revoke / anomaly: SessionRevoked + bitmap flip.
```

## 3. The interface

Full surface in [`interfaces/contracts/IEphemeralSessionKeyManager.sol`](../interfaces/contracts/IEphemeralSessionKeyManager.sol). Compatible with ERC-4337 v0.7 (`EntryPoint` v0.7).

Headline:

| Member | Purpose |
|---|---|
| `installSessionKey(SessionKeyParams calldata p) returns (bytes32 sessionId)` | Patronus calls after F1 consent. Emits `SessionIssued`. |
| `revokeSessionKey(bytes32 sessionId, bytes32 reasonCode)` | Manual / automated revocation. Emits `SessionRevoked` + bitmap flip. |
| `validateUserOp(...)` | ERC-4337 v0.7 hook. **Stateless** (see F7). Verifies signature **and** policy. |
| `isRevoked(bytes32 sessionId) view returns (bool)` | Bitmap-backed; cheap to read. |
| `listActiveSessions(bytes32 pairwiseCommitment) view returns (bytes32[])` | Powers Patronus's F8 audit UX. |

The `SessionKeyParams` struct includes:

| Field | Purpose |
|---|---|
| `pubKey` | The session key's address. |
| `pairwiseCommitment` | Bound to a specific pairwise DID. |
| `parentSessionId` | F3 — `bytes32(0)` for root sessions; otherwise the parent. |
| `validUntil` | Expiry (uint48). |
| `maxValueWei` | Per-UserOp value cap. |
| `allowedSelectors` | 4-byte function selectors permitted. |
| `policyHash` | keccak256 of the full off-chain `SharedStructs.SessionPolicy`. |
| `requiredAal` | NIST 800-63B-4 AAL minimum (1, 2, 3). |

## 4. Pairwise DID binding

Every session key is bound to a pairwise DID commitment ([ADR-0003](adr/ADR-0003-pairwise-dids-persona-abstraction.md)). Concretely:

- The session key is derived from `HKDF(rootSecret, dappOrigin || sessionSalt)`.
- The `pairwiseCommitment` carried in the on-chain `SessionIssued` event is the public commitment of the dApp-specific persona; the root DID is never visible.
- Two dApps cannot correlate the same user across their sessions without breaking HKDF.

## 5. F2 — Hardware-backed authenticator at Moderate+

For Moderate and High risk tiers, the consent ceremony in step 3 of §2 requires a **hardware-backed** authenticator:

- Apple Secure Enclave / Touch ID / Face ID
- Android StrongBox / TEE-backed Keystore
- Yubikey / SoloKey / TitanKey / any FIDO2 device with hardware attestation
- TPM 2.0 platform key

Synced passkeys (iCloud Keychain, Google Password Manager, 1Password sync) are accepted **only at the Low risk tier**, because they lack hardware attestation about device provenance — see Scott Helme's "XSS Is Deadly for Passkeys" research (V5) and the DEF CON 33 (Aug 2025) prompt spoofing demonstration (V4).

Patronus verifies hardware-backing via:
- FIDO Metadata Service (MDS3) lookup of the authenticator's `aaguid`, **and/or**
- Platform attestation (App Attest / SafetyNet / Play Integrity / Secure Enclave key attestation) per F5 in the HumanKey docs.

The on-chain `SessionPolicy.requiredAal` field lets ERC-4337 validators enforce this without trusting off-chain state.

## 6. F7 — ERC-4337 session-key hardening

The single most important security ADR for this layer: [ADR-0007](adr/ADR-0007-erc4337-session-key-hardening.md). Mandates:

1. **Decode and inspect inner calldata.** A session key scoped to `router.swap()` must verify the inner call is in fact `swap`, not `multicall(approve, MAX_UINT)`.
2. **Denylist pass-through forwarders.** `multicall`, `aggregate`, `execute(bytes[])`, `executeBatch`, and any function that forwards arbitrary calldata to the same contract are categorically rejected unless explicitly whitelisted with their own per-inner-call scope.
3. **Sign over gas fields.** `userOpHash` must include `callGasLimit`, `verificationGasLimit`, `preVerificationGas`, `maxFeePerGas`, `maxPriorityFeePerGas`. Excluding any of these lets an attacker rewrite gas to drain ETH (Trail of Bits Mar 2026).
4. **Sign over chain-id.** Defeats cross-chain UserOp replay (V26).
5. **Stateless validators.** `validateUserOp` MUST NOT write storage. State written during validation can be overwritten by another op in the same bundle before this op executes (Trail of Bits 2026).
6. **Per-token spending caps at the transfer event, not the call site.** If the policy says "max $50 USDC", enforce that on the actual `Transfer(...USDC...)` event, not on the function signature.

NatSpec on `IEphemeralSessionKeyManager.sol` cites this ADR for each method.

## 7. F8 — Periodic session audit

Patronus surfaces a quarterly "stale session" review:

```
listActiveSessions(pairwiseCommitment?) → SessionSummary[]
```

For each session: `sessionId`, `dappOrigin`, `installedAt`, `lastUsedAt`, `validUntil`, `scope summary`, `parent`. One-click revoke per session; bulk revoke per dApp.

The audit defeats V28 (dormant OAuth grants — CSA Quarterly review never happens; Patronus makes it a UX moment).

## 8. Cross-chain replay defense

Per F7.4 and [ADR-0007](adr/ADR-0007-erc4337-session-key-hardening.md): every signed `userOpHash` includes `block.chainid`. A UserOp signed for Base will fail validation if replayed on Arbitrum (different chain id → different hash → signature mismatch).

## 9. DPoP / sender-constrained semantics

Off-chain interactions (REST APIs, GraphQL, WebSocket subscriptions) that need a bearer-equivalent token MUST use the session key as a **DPoP key** (RFC 9449):

- The session key signs a DPoP proof per request.
- The resource server verifies the proof against the session key's public half (looked up by `sessionId`).
- Stolen bearer tokens are useless without the session key, and the session key never leaves Patronus.

This makes Keychain sessions sender-constrained by construction (V16). A future Keychain-DPoP profile doc will formalize the JWK shape.

## 10. Failure modes

| Failure | Mitigation |
|---|---|
| Session policy underspecified (V24 multicall escape) | F7.1, F7.2 enforced in NatSpec; rejected at validate. |
| Attacker rewrites gas fields (V25) | F7.3 — gas fields in signed hash. |
| Cross-chain replay (V26) | F7.4 — chain id in signed hash. |
| Validator state pollution (V27) | F7.5 — stateless validators. |
| User loses Patronus device with active sessions | Sessions auto-expire at `validUntil`; HumanKey lineage recovery handles long-term remediation. |
| LLM coerced into signing arbitrary calldata via prompt injection (V14) | F4 — Patronus signing requests above Low always require out-of-DOM consent (F1). |

## 11. Open questions

- Default session lifetime: 15 minutes for High-risk dApps, 1 hour for Moderate, 24 hours for Low. Tunable per dApp by user policy.
- DPoP profile spec — deferred to v2, but session key shape is forward-compatible.
- Whether to support BLS aggregated session signatures for AI-agent fleets — out of scope for v1.

## 12. Acceptance criteria

1. The interface in [`IEphemeralSessionKeyManager.sol`](../interfaces/contracts/IEphemeralSessionKeyManager.sol) matches §3 exactly and references [ADR-0007](adr/ADR-0007-erc4337-session-key-hardening.md).
2. The `SessionPolicy` field order matches `SharedStructs.SessionPolicy` (cross-repo contract).
3. F2 (hardware-backed at Moderate+) is enforced both off-chain (Patronus MDS3 check) and on-chain (`requiredAal`).
4. F7 hardening rules are reflected as NatSpec on `validateUserOp`.
5. F8 audit method is present and references `04-patronus-guardian.md` §1.7.
