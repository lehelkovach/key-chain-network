// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  StorageNetOps
/// @notice Op-code constants for `IStorageNetGateway`. In a library because
///         Solidity interfaces cannot declare constants.
library StorageNetOps {
    /// @dev  0 = read, 1 = write, 2 = delete, 3 = keyRotate.
    uint8 internal constant OP_READ       = 0;
    uint8 internal constant OP_WRITE      = 1;
    uint8 internal constant OP_DELETE     = 2;
    uint8 internal constant OP_KEYROTATE  = 3;
}

/// @title  IStorageNetGateway
/// @notice The Layer 3 (StorageNet) access gateway. Enforces the
///         **log-before-serve** invariant: every read / write / delete /
///         key-rotate MUST emit `AccessLogged` to Layer 1 BEFORE the data
///         plane responds. See `docs/03-layer3-storagenet.md` §3.
/// @dev    Gateway nodes are slashable for violations of this invariant.
///         Op codes live in `StorageNetOps` (above).
interface IStorageNetGateway {
    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted BEFORE the gateway returns any bytes to the caller.
    /// @dev    Mirrors the canonical `StorageAccess` event in
    ///         `events/IConspicuousUsageEvents.sol`.
    event AccessLogged(
        bytes32 indexed ticketId,
        bytes32 objectId,
        bytes32 pairwiseCommitment,
        uint8 op
    );

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error UnauthorizedAccess();
    error InvalidAuthProof();
    error ObjectNotFound(bytes32 objectId);
    error DagUnreachable();
    error InvariantViolation_LogBeforeServe();

    // -------------------------------------------------------------------------
    // External — read / write / delete / rotate
    // -------------------------------------------------------------------------

    /// @notice Request to read an object. The gateway:
    ///          1. Verifies `authProof` proves the caller is authorized
    ///             for `(objectId, pairwiseCommitment)`.
    ///          2. Emits `AccessLogged(OP_READ, ...)` to L1 and AWAITS
    ///             inclusion acknowledgement.
    ///          3. Only then returns the encrypted blob via a separate
    ///             out-of-band channel keyed by `ticketId`.
    /// @return ticketId A handle the caller uses to retrieve the bytes.
    function requestRead(
        bytes32 objectId,
        bytes32 pairwiseCommitment,
        bytes calldata authProof
    ) external returns (bytes32 ticketId);

    /// @notice Request to write or update an object.
    /// @param  contentHash    Hash of the encrypted ciphertext being written.
    /// @return ticketId       Handle for completing the write.
    function requestWrite(
        bytes32 objectId,
        bytes32 contentHash,
        bytes32 pairwiseCommitment,
        bytes calldata authProof
    ) external returns (bytes32 ticketId);

    /// @notice Request to delete an object.
    function requestDelete(
        bytes32 objectId,
        bytes32 pairwiseCommitment,
        bytes calldata authProof
    ) external returns (bytes32 ticketId);

    /// @notice Rotate the per-object key (e.g., on reader revocation).
    ///         The caller supplies a commitment to the new wrapped-key set;
    ///         existing readers whose wraps are not included lose future
    ///         access.
    function rotateObjectKey(
        bytes32 objectId,
        bytes32 pairwiseCommitment,
        bytes32 newKeyCommitment,
        bytes calldata authProof
    ) external returns (bytes32 ticketId);

    // -------------------------------------------------------------------------
    // External — view
    // -------------------------------------------------------------------------

    /// @notice Look up the latest content-hash for an object.
    function getContentHash(bytes32 objectId, bytes32 pairwiseCommitment)
        external
        view
        returns (bytes32);

    // IMPLEMENTATION NOTES:
    // - The gateway MUST commit the access event to L1 BEFORE serving any
    //   bytes. If L1 commit fails, the request MUST fail with `DagUnreachable`.
    //   This is the load-bearing security invariant of Layer 3.
    // - Gateway nodes that violate log-before-serve are provably guilty
    //   (mismatched DAG state vs served bytes). Stake slashed.
    // - The actual ciphertext is served via a separate data-plane endpoint
    //   keyed by `ticketId`. This contract is the control plane.
    // - `authProof` may be a signature by an ephemeral session key, a ZK
    //   proof of pairwise-DID ownership, or a verifier-defined custom shape.
    //   The gateway dispatches by `authProof[0]` (proof-type byte).
    // - Object IDs are content-addressed; collisions are not a concern at
    //   the cryptographic level.
    // - Storage nodes never see plaintext; XChaCha20-Poly1305 is applied
    //   client-side (in Patronus) before any data ever reaches a gateway.
}
