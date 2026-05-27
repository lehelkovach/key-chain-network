# ADR-0007 — ERC-4337 Session-Key Hardening

**Status:** Proposed
**Date:** 2026-05-27
**Deciders:** Keychain protocol architecture
**Addresses:** F7; mitigates V24 (multicall escape), V25 (sig validation gaps), V26 (cross-chain replay), V27 (state-modify during validation)

## Context

ERC-4337 v0.7 is the substrate Keychain uses for ephemeral session keys. Public audits and incident research in 2024–2026 identified a small set of high-impact mistakes that recur across many AA implementations:

- **Trail of Bits — "Six mistakes in ERC-4337 smart accounts"** (Mar 2026).
- **RedVolt — "Account Abstraction Security: The New Attack Surface Nobody's Auditing"** (2026).
- **OpenZeppelin incremental audit (Jan 2024)** of `eth-infinitism/account-abstraction`.
- **Spearbit review** (v0.8/v0.9 cycle, 2025).

The recurring critical bug is **session-key over-permissioning**: a key scoped to `router.swap()` is whitelisted by target address only; the attacker calls `router.multicall(approve, MAX_UINT)` and drains the wallet because the validator never decoded the inner calldata. Other recurring bugs: signing over a hash that excludes gas fields (attacker rewrites gas to drain ETH); state writes during validation that can be overwritten by another op in the same bundle; missing chain-id allowing cross-chain replay.

Any session-key validator Keychain ships must encode mitigations for all of these.

## Decision

**`IEphemeralSessionKeyManager.validateUserOp` MUST satisfy all of the following invariants. Implementations that violate any of these are non-conformant and must not be merged.**

### Hardening rule set

1. **Decode and inspect inner calldata.** Session policy specifies `allowedSelectors` — a list of 4-byte function selectors. The validator MUST verify the **outer** call's selector is in the list **and** decode any nested calls (multicall / aggregate / execute-batch shapes) to verify every **inner** selector is in the list. A policy that lists `swap` does not permit `multicall(approve, swap)` unless `approve` is also explicitly listed.

2. **Denylist pass-through forwarders.** The following selectors (and equivalents) are categorically rejected unless the session policy explicitly opts in *and* re-enumerates the inner scope:
   - `multicall(bytes[])` — selector `0xac9650d8`
   - `aggregate((address,bytes)[])` — selector `0x252dba42`
   - `execute(address,uint256,bytes)` — selector `0xb61d27f6` (when called as a forwarder)
   - `executeBatch((address,uint256,bytes)[])` — selector varies
   - `delegateCall(address,bytes)` — categorically forbidden
   - Any function whose ABI shape includes nested arbitrary `bytes` payloads to the same contract.
   The maintained denylist lives alongside the validator as a versioned table.

3. **Sign over gas fields.** `userOpHash` MUST commit to:
   - `callGasLimit`
   - `verificationGasLimit`
   - `preVerificationGas`
   - `maxFeePerGas`
   - `maxPriorityFeePerGas`
   - `paymasterAndData` (if present)
   Excluding any of these lets an attacker rewrite gas to drain ETH from the user (Trail of Bits Mar 2026).

4. **Sign over chain-id.** `userOpHash` MUST commit to `block.chainid`. Defeats cross-chain UserOp replay (V26). Use the EntryPoint v0.7 `getUserOpHash` helper.

5. **Stateless validation.** `validateUserOp` MUST NOT write to storage. State written during validation can be overwritten by another op in the same bundle before this op executes (EntryPoint validates all ops in a bundle before executing any). Stateful checks (e.g., spending caps) MUST be enforced as **effect-based assertions in `execute`**, not as validation-time storage.

6. **Per-token spending caps at the transfer event, not the call site.** If the policy says "max $50 USDC per session", enforce that on the actual `Transfer(...USDC...)` event emitted during execution, not on the function signature. This defeats clever encodings that move value without invoking the named function.

### Required behavior

- Validators MUST reject UserOps that violate any rule with a specific error (`CallDataNotInScope`, `ForwarderDenied`, `GasFieldsNotSigned`, `ChainIdMismatch`, `StatefulValidationForbidden`, `EffectCapExceeded`).
- Validators MUST emit `SessionUsed` only after a successful validation **and** successful execution.
- Failed validation MUST emit `SessionReused` (with reason) if it looks like a replay, otherwise no event (to avoid signaling validation paths to attackers).

### Audit hooks

- The session-key manager MUST expose a view function `simulateCalldataPolicy(bytes32 sessionId, bytes calldata callData) view returns (bool allowed, bytes32 reasonCode)` so Patronus can pre-flight a UserOp before signing.

## Consequences

**Positive:**
- Eliminates the most-cited session-key vulnerability class in the 2026 audit literature.
- Forces session-key validators to be **stateless**, which improves bundler compatibility and prevents one-op-poisons-another bugs.
- Provides a clean simulate path for Patronus to surface "this UserOp will be rejected" to the user *before* signing.

**Negative:**
- Calldata decoding adds gas to validation. Acceptable; validation gas is already bounded by EntryPoint limits.
- Denylist must be maintained as new forwarder patterns emerge (e.g., new multicall variants). Treat as a living document with notary-governed updates per ADR-0002.
- Some dApps that legitimately use multicall for batched UX will need to opt-in via explicit scope and re-enumeration.

## Alternatives considered

- **Target-address-only whitelist** — the status quo in most implementations; explicitly rejected. This is the bug.
- **No nested decoding; rely on user re-prompting per inner call** — rejected (UX failure; defeats the purpose of session keys).
- **EIP-7702 + traditional EOA keys** — orthogonal; 7702 helps with the account model but doesn't fix scope enforcement.
- **Single global denylist enforced at the EntryPoint level** — better in theory; impractical as v1 because EntryPoint is shared infrastructure.

## Open questions

- Exact denylist surface — needs ongoing curation as new forwarder patterns appear.
- Whether to allow `delegateCall` under any circumstances — current decision is no; revisit if a compelling use case emerges.
- Gas-cost benchmarking of full inner-decode validation; if it exceeds reasonable limits, consider a precompile.

## References

- `docs/06-erc4337-ephemeral-keys.md` §6
- Trail of Bits — "Six mistakes in ERC-4337 smart accounts" (Mar 2026).
- RedVolt — "Account Abstraction (ERC-4337) Security" (2026).
- OpenZeppelin — "ERC-4337 Account Abstraction Incremental Audit" (Jan 2024).
- Spearbit review notes (v0.8/v0.9, 2025).
- ERC-4337 v0.7 EntryPoint spec.
