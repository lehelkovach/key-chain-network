// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  IKeychainAnchor
/// @notice The Layer 2 settlement contract for Keychain's high-throughput
///         Layer 1 BlockDAG. Per-epoch Merkle commitments and ZK pruning
///         proofs land here. Anchored roots inherit Ethereum's economic
///         security via the host L2 (Base in v1; see ADR-0004).
/// @dev    Designed for ERC-1967-style proxy deployment. Implementation is
///         upgradeable ONLY through `IKeychainUpgradeGovernor`
///         (ADR-0002 — Web-of-Trust Proxy Upgrade). There is NO admin key.
interface IKeychainAnchor {
    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice A new DAG epoch was successfully anchored.
    /// @param  epoch        Monotonic epoch number.
    /// @param  root         Merkle root of all event IDs in the epoch.
    /// @param  zkProofHash  keccak256 of the ZK proof bytes (full proof
    ///                      retrievable from calldata for the same tx).
    event EpochAnchored(uint64 indexed epoch, bytes32 root, bytes32 zkProofHash);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @notice Caller submitted a non-increasing epoch number.
    error EpochStale(uint64 submitted, uint64 latest);

    /// @notice This epoch was already anchored.
    error EpochAlreadyAnchored(uint64 epoch);

    /// @notice The ZK proof failed verification.
    error InvalidZkProof();

    /// @notice The caller is not authorized to commit epochs.
    /// @dev    Only the rotating anchor-proposer (selected per epoch via VRF)
    ///         may call `commitEpoch`.
    error UnauthorizedProposer(address caller);

    // -------------------------------------------------------------------------
    // External — anchor write path
    // -------------------------------------------------------------------------

    /// @notice Commit a new DAG epoch's Merkle root + ZK proof to L2.
    /// @param  dagStateRoot Merkle root over the epoch's event IDs.
    /// @param  zkProof      Recursive ZK proof of correct accumulation
    ///                      (and, on pruning epochs, of correct summarization
    ///                      of pruned events; see ADR-0001).
    /// @param  epoch        Epoch number being anchored. Must be exactly
    ///                      `latestEpoch() + 1`.
    function commitEpoch(
        bytes32 dagStateRoot,
        bytes calldata zkProof,
        uint64 epoch
    ) external;

    // -------------------------------------------------------------------------
    // External — view
    // -------------------------------------------------------------------------

    /// @notice Get the anchored root for a specific epoch.
    /// @return root `bytes32(0)` if not yet anchored.
    function getEpochRoot(uint64 epoch) external view returns (bytes32 root);

    /// @notice Get the most recently anchored epoch number.
    function latestEpoch() external view returns (uint64);

    /// @notice Verify a Merkle inclusion proof for an event ID against an
    ///         anchored root.
    /// @param  epoch    Epoch whose root to verify against.
    /// @param  eventId  Leaf hash.
    /// @param  proof    Merkle path from leaf to root.
    function verifyInclusion(
        uint64 epoch,
        bytes32 eventId,
        bytes32[] calldata proof
    ) external view returns (bool);

    // IMPLEMENTATION NOTES:
    // - Storage layout (target):
    //     mapping(uint64 => bytes32) private _roots;     // epoch => root
    //     uint64 private _latestEpoch;
    //     address private _vrfCoordinator;               // for proposer selection
    //     address private _zkVerifier;                   // upgradeable via governor
    // - `commitEpoch` MUST be reentrancy-protected.
    // - The ZK verifier contract is itself upgradeable through the governor.
    // - For optimistic L2s with a 7-day challenge period, finality at the
    //   L1 Ethereum level lags by 7 days; for protocol-level finality the
    //   anchored event is enough.
    // - Future v2: emit a Patronus-subscribable CAEP `assurance-level-change`
    //   event when an epoch contains AnomalyDetected at severity >= threshold.
}
