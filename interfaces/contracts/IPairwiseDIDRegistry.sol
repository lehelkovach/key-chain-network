// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  IPairwiseDIDRegistry
/// @notice On-chain registry of pairwise DID **commitments** (never the
///         root DID, never the mapping back). See ADR-0003.
/// @dev    The registry stores only `keccak256(pairwiseDid.publicKey)`. The
///         pairwise DID itself is shared off-chain with the bound dApp via
///         the standard W3C DID resolution flow. The root DID is never
///         knowable from on-chain state.
interface IPairwiseDIDRegistry {
    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice A new pairwise commitment was registered.
    /// @dev    There is NO event that links commitments to a root identity.
    ///         By design.
    event PairwiseRegistered(
        bytes32 indexed pairwiseCommitment,
        uint64 indexed epoch
    );

    /// @notice A pairwise commitment was rotated (e.g., as part of lineage
    ///         recovery on the HumanKey side).
    event PairwiseRotated(
        bytes32 indexed oldCommitment,
        bytes32 indexed newCommitment,
        uint64 epoch
    );

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error AlreadyRegistered(bytes32 pairwiseCommitment);
    error InvalidDerivationProof();
    error UnknownCommitment(bytes32 pairwiseCommitment);

    // -------------------------------------------------------------------------
    // External — registration
    // -------------------------------------------------------------------------

    /// @notice Register a pairwise commitment with a ZK proof that the
    ///         caller holds a root secret from which the commitment is
    ///         correctly derived via HKDF and a stated dApp origin.
    /// @dev    The proof attests:
    ///           "I know a rootSecret such that
    ///            pairwiseCommitment = H(HKDF(rootSecret, 'pairwise-did' || dappOrigin))"
    ///         without revealing rootSecret or dappOrigin. dappOrigin is
    ///         included as a public input.
    /// @param  pairwiseCommitment   The bytes32 commitment to register.
    /// @param  dappOriginHash       keccak256 of the dApp origin scheme://host:port
    ///                              (path/query do NOT participate).
    /// @param  zkProofOfDerivation  Groth16 / Plonk proof per the circuit
    ///                              defined in the ZK toolchain ADR (HumanKey ADR-0005).
    function registerCommitment(
        bytes32 pairwiseCommitment,
        bytes32 dappOriginHash,
        bytes calldata zkProofOfDerivation
    ) external;

    /// @notice Rotate a pairwise commitment to a new one. Used by HumanKey's
    ///         lineage-preserving recovery flow; the old commitment is
    ///         marked rotated but NOT deleted (for audit continuity).
    /// @param  oldCommitment       Existing commitment.
    /// @param  newCommitment       Replacement commitment.
    /// @param  zkProofOfRotation   Proof that both commitments derive from
    ///                             the same root and the same dApp origin.
    function rotateCommitment(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        bytes calldata zkProofOfRotation
    ) external;

    // -------------------------------------------------------------------------
    // External — view
    // -------------------------------------------------------------------------

    function isRegistered(bytes32 pairwiseCommitment)
        external
        view
        returns (bool);

    /// @notice Returns the current (potentially rotated) commitment for an
    ///         original one. Returns the input if it has never been rotated.
    function currentCommitment(bytes32 originalCommitment)
        external
        view
        returns (bytes32);

    /// @notice The epoch in which this commitment was first registered.
    function registrationEpoch(bytes32 pairwiseCommitment)
        external
        view
        returns (uint64);

    // IMPLEMENTATION NOTES:
    // - Storage layout (target):
    //     mapping(bytes32 => bool)    private _registered;
    //     mapping(bytes32 => uint64)  private _registrationEpoch;
    //     mapping(bytes32 => bytes32) private _rotation; // old => new
    // - The ZK verifier contract is upgradeable via the governor (so the
    //   underlying circuit can be revved without invalidating the registry).
    // - Rotation is one-way; the old commitment cannot be reused.
    // - Anyone can query `isRegistered` (necessary for relying parties to
    //   verify a counterparty's pairwise identity exists), but the registry
    //   exposes NO function from commitment -> root or commitment -> dApp
    //   origin. The dApp origin participates only in the proof's public
    //   inputs and is hashed.
}
