// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// =============================================================================
// SHARED: This file is the source of truth for the Conspicuous Usage event
// taxonomy. Both `key-chain-network` and `lehelkovach/human-key-core` import
// these event signatures. DO NOT MODIFY without coordinating across both repos.
// =============================================================================

/// @title IConspicuousUsageEvents
/// @notice Canonical event signatures emitted by Keychain Layer 1 (BlockDAG)
///         and by HumanKey contracts that delegate audit telemetry through
///         Keychain. Every identity-affecting action in either protocol MUST
///         emit one of these events.
/// @dev    "Conspicuous Usage" is the core security principle of the Keychain
///         Protocol: no identity action is silent. Every emission of one of
///         these events causes the Patronus Guardian on the user's device to
///         surface an alert and start (or reset) the 24h dispute window.
///         See `docs/05-conspicuous-usage.md` for the lifecycle.
///
///         Event signatures are also serialized to the OpenID Continuous
///         Access Evaluation Profile (CAEP) wire format via
///         `interfaces/ts/caep-emitter.ts` (see ADR-0008). Any field changes
///         here therefore require a parallel update to the CAEP profile.
interface IConspicuousUsageEvents {
    // -------------------------------------------------------------------------
    // Session lifecycle (Keychain-emitted)
    // -------------------------------------------------------------------------

    /// @notice A new ERC-4337 ephemeral session key was installed for a
    ///         pairwise DID.
    /// @param  pairwiseCommitment Hash commitment of the pairwise DID
    ///         (derived per `(rootDid, dappOrigin)`; root never appears).
    /// @param  sessionId          Opaque session identifier.
    /// @param  parentSessionId    `bytes32(0)` if root session; otherwise the
    ///         parent session this one was derived from (F3 consent
    ///         transitivity — sub-session scope MUST ⊆ parent scope).
    /// @param  policyHash         Hash of the session's policy
    ///         (allowedSelectors, maxValueWei, validUntil, etc.).
    /// @param  validUntil         Session expiry (unix seconds).
    /// @param  timestamp          Emission time (unix seconds).
    event SessionIssued(
        bytes32 indexed pairwiseCommitment,
        bytes32 indexed sessionId,
        bytes32 parentSessionId,
        bytes32 policyHash,
        uint64  validUntil,
        uint64  timestamp
    );

    /// @notice A session key was used to sign a UserOp / action.
    event SessionUsed(
        bytes32 indexed pairwiseCommitment,
        bytes32 indexed sessionId,
        bytes32 actionHash,
        uint64  timestamp
    );

    /// @notice A session key was revoked (manually, by policy, or by anomaly).
    /// @param  reasonCode keccak256-encoded reason (e.g., "user","expired","anomaly","stolen").
    event SessionRevoked(
        bytes32 indexed pairwiseCommitment,
        bytes32 indexed sessionId,
        bytes32 reasonCode,
        uint64  timestamp
    );

    /// @notice A reused session attempt was detected (Conspicuous Usage trip).
    /// @dev    The user must see this within seconds. Combined with the 24h
    ///         dispute window, makes AiTM cookie theft (V1) observable.
    event SessionReused(
        bytes32 indexed pairwiseCommitment,
        bytes32 indexed sessionId,
        bytes32 actionHash,
        uint64  timestamp
    );

    // -------------------------------------------------------------------------
    // Delegation / agent action (Keychain-emitted)
    // -------------------------------------------------------------------------

    /// @notice A delegation was granted (e.g., user → AI agent, agent → sub-agent).
    /// @dev    `parentSessionId` enforces F3 consent transitivity: the
    ///         delegated scope MUST be a subset of the parent's scope.
    event DelegationGranted(
        bytes32 indexed pairwiseCommitment,
        bytes32 indexed sessionId,
        bytes32 parentSessionId,
        address delegatee,
        bytes32 scopeHash,
        uint64  validUntil,
        uint64  timestamp
    );

    /// @notice An AI agent (or any delegated identity) took an action under a
    ///         delegated session.
    event AgentAction(
        bytes32 indexed pairwiseCommitment,
        bytes32 indexed sessionId,
        address actor,
        bytes32 actionHash,
        uint64  timestamp
    );

    // -------------------------------------------------------------------------
    // Storage (Keychain-emitted; Layer 3 invariant: log-before-serve)
    // -------------------------------------------------------------------------

    /// @notice A StorageNet object was accessed (read=0, write=1, delete=2,
    ///         keyRotate=3). Emitted BEFORE the data plane responds.
    event StorageAccess(
        bytes32 indexed objectId,
        bytes32 indexed pairwiseCommitment,
        uint8   op,
        bytes32 ticketId,
        uint64  timestamp
    );

    // -------------------------------------------------------------------------
    // Anomaly (Keychain-emitted; emitted on Adaptive Escalation High deny)
    // -------------------------------------------------------------------------

    /// @notice Anomalous behavior detected (e.g., HumanKey High-tier deny,
    ///         atypical geo, cookie replay, etc.).
    /// @param  severity 0..65535 (higher = more severe).
    event AnomalyDetected(
        bytes32 indexed pairwiseCommitment,
        bytes32 reasonCode,
        uint16  severity,
        uint64  timestamp
    );

    // -------------------------------------------------------------------------
    // HumanKey-emitted (subset of the taxonomy — full definitions in
    // `lehelkovach/human-key-core/interfaces/contracts/events/IHumanKeyEvents.sol`)
    // -------------------------------------------------------------------------

    /// @notice One of the three tribunal notaries signed an attestation for a
    ///         pending HumanKey mint request.
    event NotaryAttestation(
        bytes32 indexed pairwiseCommitment,
        address indexed notary,
        uint256 indexed mintRequestId,
        bytes32 teeAttestationHash,
        uint64  timestamp
    );

    /// @notice A HumanKey zkNFT was minted.
    /// @param  sponsor `address(0)` if self-funded; otherwise the sponsor's
    ///         address (P5 Sponsorship Protocol).
    event Minted(
        uint256 indexed zkNftId,
        bytes32 indexed pairwiseCommitment,
        address sponsor,
        uint64  timestamp
    );

    /// @notice A lineage-preserving recovery has been initiated.
    event RecoveryInitiated(
        uint256 indexed oldZkNftId,
        bytes32 indexed newCommitment,
        uint64  delayWindowEnd,
        uint64  timestamp
    );

    /// @notice A successful rebind — new zkNFT references old as lineage anchor.
    /// @param  chainLength Number of lineage anchors in the chain (1 for first rebind).
    event LineageRebound(
        uint256 indexed oldZkNftId,
        uint256 indexed newZkNftId,
        uint32  chainLength,
        uint64  timestamp
    );

    /// @notice Inheritance state machine tick (Alive=0, Stale=1, Grace=2,
    ///         Claimable=3, Claimed=4, Cancelled=5).
    event InheritanceTick(
        uint256 indexed zkNftId,
        uint64  lastProofOfLife,
        uint8   state,
        uint64  timestamp
    );

    // IMPLEMENTATION NOTES:
    // - DAG nodes MUST index events by `pairwiseCommitment` for Patronus
    //   subscription queries.
    // - Every event MUST also be serialized into a CAEP Security Event Token
    //   (SET) per ADR-0008 so that any CAEP-compliant receiver can consume
    //   Keychain telemetry without a custom integration.
    // - The Patronus Guardian alert pipeline MUST deliver these events to the
    //   user's device within one DAG inclusion epoch (target: <2s) and start
    //   the 24h dispute window (configurable per user; floor 1h).
    // - On HumanKey side, the `NotaryAttestation` / `Minted` / `RecoveryInitiated`
    //   / `LineageRebound` / `InheritanceTick` events are emitted by HumanKey
    //   contracts but consumed by the same Keychain DAG infrastructure. The
    //   HumanKey repo re-declares these events in its own
    //   `events/IHumanKeyEvents.sol` with identical signatures.
}
