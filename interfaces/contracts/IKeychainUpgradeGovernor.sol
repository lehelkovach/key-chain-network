// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  IKeychainUpgradeGovernor
/// @notice The Web-of-Trust proxy upgrade controller. All upgradeable
///         Keychain contracts route their proxy admin to this governor.
///         There is NO developer admin key.
/// @dev    ADR-0002. Bootstrap notary set comes from the HumanKey bonded
///         federation (HumanKey ADR-0009 / Pivot P5); bonds decay over 24 months.
interface IKeychainUpgradeGovernor {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    /// @notice Proposal lifecycle state.
    enum ProposalState {
        Pending,    // 0 — created, voting open
        Approved,   // 1 — quorum + super-majority reached, in timelock
        Executed,   // 2 — applied
        Cancelled,  // 3 — withdrawn before execution
        Defeated    // 4 — voting closed without quorum / super-majority
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proxy,
        address newImplementation,
        bytes32 reasonHash,
        address proposer,
        uint64  timelockEnd
    );

    event Voted(
        uint256 indexed proposalId,
        address indexed notary,
        bool    support
    );

    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId);
    event ProposalDefeated(uint256 indexed proposalId);

    /// @notice Emergency pause is a restricted variant requiring higher
    ///         super-majority and a shorter timelock. Only pauses; cannot
    ///         swap implementation.
    event EmergencyPaused(address indexed proxy, uint256 indexed proposalId);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error NotAnActiveNotary(address caller);
    error AlreadyVoted(uint256 proposalId, address notary);
    error InsufficientQuorum();
    error InsufficientSuperMajority();
    error TimelockNotElapsed(uint64 elapsesAt);
    error InvalidProposalState(ProposalState state);
    error ProxyNotGoverned(address proxy);

    // -------------------------------------------------------------------------
    // External — propose / vote / execute
    // -------------------------------------------------------------------------

    /// @notice Open a new upgrade proposal. Any address may propose with a
    ///         small bond (see `proposalBond()`).
    /// @param  proxy             The proxy whose implementation to change.
    /// @param  newImplementation The candidate implementation address.
    /// @param  reason            Free-form human-readable reason (hashed
    ///                           on-chain for cheap storage; full body in
    ///                           StorageNet).
    /// @return proposalId        Monotonic per-governor proposal ID.
    function propose(
        address proxy,
        address newImplementation,
        bytes calldata reason
    ) external payable returns (uint256 proposalId);

    /// @notice Cast a vote as an active notary.
    /// @param  proposalId  The proposal to vote on.
    /// @param  support     True = approve, false = reject.
    /// @param  notarySig   Notary's signature over keccak256(abi.encode(
    ///                     proposalId, support, address(this), block.chainid)).
    function vote(
        uint256 proposalId,
        bool support,
        bytes calldata notarySig
    ) external;

    /// @notice Execute an approved proposal whose timelock has elapsed.
    function execute(uint256 proposalId) external;

    /// @notice Cancel a proposal (proposer-only, before approval).
    function cancel(uint256 proposalId) external;

    /// @notice Open an emergency-pause proposal. Stricter quorum (90%),
    ///         shorter timelock (24h). Pauses only; cannot replace impl.
    function proposeEmergencyPause(address proxy, bytes calldata reason)
        external
        payable
        returns (uint256 proposalId);

    // -------------------------------------------------------------------------
    // External — view
    // -------------------------------------------------------------------------

    /// @notice Default routine super-majority threshold in basis points
    ///         (e.g., 7500 = 75%).
    function routineSuperMajorityBps() external view returns (uint16);

    /// @notice Emergency super-majority threshold (default 9000 = 90%).
    function emergencySuperMajorityBps() external view returns (uint16);

    /// @notice Routine timelock in seconds (default 14 days).
    function routineTimelock() external view returns (uint64);

    /// @notice Emergency timelock in seconds (default 24 hours).
    function emergencyTimelock() external view returns (uint64);

    /// @notice Minimum participation (basis points) of active notaries to
    ///         consider any vote valid (default 1000 = 10%).
    function minQuorumBps() external view returns (uint16);

    /// @notice Per-proposal bond required (refundable on non-spam outcomes).
    function proposalBond() external view returns (uint256);

    /// @notice Root of the current notary set Merkle tree (defined by
    ///         HumanKey notary registry, sourced cross-chain).
    function notarySetRoot() external view returns (bytes32);

    function getProposalState(uint256 proposalId)
        external
        view
        returns (ProposalState);

    // IMPLEMENTATION NOTES:
    // - Storage layout (target):
    //     mapping(uint256 => Proposal) private _proposals;
    //     mapping(uint256 => mapping(address => bool)) private _hasVoted;
    //     mapping(uint256 => mapping(address => bool)) private _support;
    //     uint16 private _routineSuperMajorityBps;        // default 7500
    //     uint16 private _emergencySuperMajorityBps;      // default 9000
    //     uint64 private _routineTimelock;                // default 14 days
    //     uint64 private _emergencyTimelock;              // default 24 hours
    //     bytes32 private _notarySetRoot;
    // - Notary identity verification uses a Merkle proof against
    //   `notarySetRoot`, refreshed each L1 epoch from HumanKey's registry.
    //   This keeps the governor independent of any single notary registry
    //   instance and lets HumanKey upgrade its registry without breaking
    //   Keychain governance.
    // - Bootstrap: at deployment, `notarySetRoot` is set to the published
    //   bonded-federation set (HumanKey ADR-0009). Bonds decay over 24 months;
    //   after that the set is fully open to any qualifying notary.
    // - Emergency pause is implemented by toggling a `paused` flag on the
    //   target proxy via a separate `IPausable` interface, NOT by swapping
    //   the implementation. This is structurally important: emergency
    //   permissions cannot be used to ship new code.
}
