// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SharedStructs} from "./SharedStructs.sol";

/// @title  IEphemeralSessionKeyManager
/// @notice ERC-4337 v0.7 compatible session-key manager for Keychain.
///         Issues short-lived, scope-bounded session keys per pairwise DID.
///         Enforces the hardening rules of ADR-0007 (Flaw 7 / V24-V27).
/// @dev    A reference implementer must satisfy the following hardening
///         invariants from ADR-0007:
///           1. Decode and inspect inner calldata (no whitelist by target alone).
///           2. Denylist pass-through forwarders (multicall, aggregate, etc.).
///           3. `userOpHash` MUST commit to gas fields + paymasterAndData.
///           4. `userOpHash` MUST commit to `block.chainid`.
///           5. `validateUserOp` MUST be stateless (no storage writes).
///           6. Per-token spending caps enforced at the Transfer event, not
///              at the function call site.
interface IEphemeralSessionKeyManager {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    /// @notice Params for installing a new session key.
    /// @param  pubKey             secp256k1 address of the ephemeral key.
    /// @param  pairwiseCommitment Pairwise DID commitment this session is
    ///                            bound to (see ADR-0003).
    /// @param  parentSessionId    F3 — `bytes32(0)` if root; else parent.
    ///                            Sub-session scope MUST ⊆ parent scope.
    /// @param  validUntil         Expiry as unix seconds (uint48 fits 2^48 s).
    /// @param  maxValueWei        Per-UserOp value cap.
    /// @param  allowedSelectors   4-byte selectors permitted. The validator
    ///                            inspects nested calldata; selectors listed
    ///                            here must include any nested selector that
    ///                            would actually be invoked.
    /// @param  policyHash         keccak256 of the full off-chain
    ///                            `SharedStructs.SessionPolicy`. The on-chain
    ///                            params here are a subset; the full policy
    ///                            (geofence, requiredAal, etc.) hashes to this.
    /// @param  requiredAal        NIST 800-63B-4 AAL minimum (1, 2, 3).
    ///                            Validators reject signing requests whose
    ///                            authenticator did not meet this level.
    struct SessionKeyParams {
        address    pubKey;
        bytes32    pairwiseCommitment;
        bytes32    parentSessionId;
        uint48     validUntil;
        uint256    maxValueWei;
        bytes4[]   allowedSelectors;
        bytes32    policyHash;
        uint8      requiredAal;
    }

    /// @notice Compact summary surfaced to Patronus's F8 audit UI.
    struct SessionSummary {
        bytes32 sessionId;
        bytes32 pairwiseCommitment;
        bytes32 parentSessionId;
        uint48  validUntil;
        uint48  installedAt;
        uint48  lastUsedAt;
        bytes32 policyHash;
        bool    revoked;
    }

    // -------------------------------------------------------------------------
    // Errors (each maps to a specific ADR-0007 invariant violation)
    // -------------------------------------------------------------------------

    error CallDataNotInScope();           // §1, §2 inner-calldata decode failed
    error ForwarderDenied(bytes4 selector); // §2 multicall/aggregate denylist hit
    error GasFieldsNotSigned();           // §3 gas fields excluded from hash
    error ChainIdMismatch();              // §4 cross-chain replay
    error StatefulValidationForbidden();  // §5 storage write detected
    error EffectCapExceeded();            // §6 effect-based spending check failed

    // Other expected errors
    error SessionExpired();
    error SessionRevokedAlready();
    error SubSessionScopeViolation();     // F3 parent-scope check failed
    error AalTooLow(uint8 required, uint8 presented);
    error MissingParent();                // parentSessionId set but parent unknown

    // -------------------------------------------------------------------------
    // Events (re-declared for ABI convenience; canonical signatures in
    // events/IConspicuousUsageEvents.sol).
    // -------------------------------------------------------------------------

    event SessionInstalled(
        bytes32 indexed sessionId,
        bytes32 indexed pairwiseCommitment,
        bytes32 parentSessionId,
        bytes32 policyHash,
        uint48  validUntil
    );

    event SessionRevoked(
        bytes32 indexed sessionId,
        bytes32 reasonCode
    );

    event SessionUsed(
        bytes32 indexed sessionId,
        bytes32 actionHash
    );

    // -------------------------------------------------------------------------
    // External — install / revoke
    // -------------------------------------------------------------------------

    /// @notice Install a new session key. Called by Patronus after F1 consent.
    /// @return sessionId An opaque identifier for the session.
    function installSessionKey(SessionKeyParams calldata p)
        external
        returns (bytes32 sessionId);

    /// @notice Revoke a session. Callable by the bound pairwise identity
    ///         (via Patronus signature) or by an automated anomaly response.
    /// @param  sessionId   Session to revoke.
    /// @param  reasonCode  Keccak-keyed reason (see REASON_CODES in shared-types.ts).
    function revokeSessionKey(bytes32 sessionId, bytes32 reasonCode) external;

    // -------------------------------------------------------------------------
    // External — ERC-4337 v0.7 validator hook
    // -------------------------------------------------------------------------

    /// @notice ERC-4337 v0.7 `IAccount.validateUserOp` shape.
    /// @dev    MUST satisfy ADR-0007 hardening rules:
    ///          - decode `userOp.callData` and verify EVERY nested call's
    ///            selector is in `allowedSelectors` (rule 1);
    ///          - reject denylisted forwarder selectors unless explicitly
    ///            scoped (rule 2);
    ///          - compute `userOpHash` over gas fields + chainId (rules 3, 4);
    ///          - perform NO storage writes (rule 5);
    ///          - emit `SessionUsed` only AFTER successful execution.
    /// @param  userOp            Per ERC-4337 v0.7.
    /// @param  userOpHash        Per ERC-4337 v0.7 (caller pre-hashes).
    /// @param  missingAccountFunds Per ERC-4337 v0.7.
    /// @return validationData    Per ERC-4337 v0.7 — packed (aggregator, validUntil, validAfter).
    function validateUserOp(
        // EntryPoint v0.7 PackedUserOperation is left abstract here; the
        // implementation imports the exact struct from the EntryPoint.
        bytes calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);

    // -------------------------------------------------------------------------
    // External — view
    // -------------------------------------------------------------------------

    /// @notice Cheap revocation check (bitmap-backed).
    function isRevoked(bytes32 sessionId) external view returns (bool);

    /// @notice F8 — list active sessions for a pairwise DID, for the
    ///         Patronus session-audit UX.
    function listActiveSessions(bytes32 pairwiseCommitment)
        external
        view
        returns (SessionSummary[] memory);

    /// @notice Pre-flight a candidate UserOp's calldata against a session
    ///         policy without consuming gas as a signing attempt.
    ///         Used by Patronus to surface "this will be rejected" to the
    ///         user BEFORE signing.
    /// @return allowed     True iff the calldata satisfies the policy.
    /// @return reasonCode  bytes32(0) if allowed, otherwise the rejection reason.
    function simulateCalldataPolicy(bytes32 sessionId, bytes calldata callData)
        external
        view
        returns (bool allowed, bytes32 reasonCode);

    // IMPLEMENTATION NOTES:
    // - Storage layout (target):
    //     mapping(bytes32 => SessionKeyParams) private _sessions;
    //     mapping(bytes32 => uint256) private _revocationBitmap; // shardable
    //     mapping(bytes32 => uint48)  private _installedAt;
    //     mapping(bytes32 => uint48)  private _lastUsedAt;
    //     mapping(bytes32 => bytes32) private _parent;
    //     mapping(bytes32 => bytes4[]) private _denylistedForwarders;
    // - `validateUserOp` MUST be stateless: do not write _lastUsedAt or
    //   anything else from validation. Update _lastUsedAt from `execute`
    //   instead (a SessionUsed event in the EntryPoint post-execution hook).
    // - F3 consent transitivity: when validating a UserOp signed by a child
    //   session, walk up _parent (bounded by Patronus policy max-depth 4)
    //   and verify every ancestor is non-revoked AND scope-monotonic.
    // - The denylisted forwarder set is itself versioned and updateable via
    //   the upgrade governor (ADR-0002).
    // - For DPoP / off-chain compatibility (06-erc4337-ephemeral-keys.md §9),
    //   the session key MAY be exposed via a JWKS endpoint by Patronus.
    //   The on-chain manager does not need to participate.
}
