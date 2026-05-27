// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// =============================================================================
// SHARED: This file is the source of truth for Solidity structs that cross
// the boundary between Keychain (this repo) and HumanKey
// (lehelkovach/human-key-core). DO NOT MODIFY without coordinating across
// both repos. The corresponding TypeScript types live in
// `interfaces/ts/shared-types.ts`.
// =============================================================================

/// @title SharedStructs
/// @notice Cross-protocol struct definitions used by both Keychain and HumanKey.
///         Defined in a library so callers can `using` or refer via the
///         fully-qualified path.
library SharedStructs {
    // -------------------------------------------------------------------------
    // Notary attestation — issued during the 3-of-3 tribunal mint process
    // and the 2-of-3 recovery attestation process.
    // -------------------------------------------------------------------------

    /// @notice One notary's signed attestation in a HumanKey tribunal.
    /// @param  notary            Notary's on-chain identity (EOA or BLS aggregator).
    /// @param  mintRequestId     The mint or recovery request ID this attests to.
    /// @param  approve           True if the notary approves, false if rejects.
    /// @param  teeAttestationRef Hash of the LivenessAttestation the notary
    ///                           verified (anchors the notary's claim to a
    ///                           specific TEE-witnessed liveness check).
    /// @param  signature         Notary's signature over keccak256(
    ///                           abi.encode(mintRequestId, approve, teeAttestationRef)).
    struct NotaryAttestation {
        address notary;
        uint256 mintRequestId;
        bool    approve;
        bytes32 teeAttestationRef;
        bytes   signature;
    }

    // -------------------------------------------------------------------------
    // Liveness attestation — produced by the Confidential TEE Oracle
    // (HumanKey ADR-0001) for High-tier authentication actions.
    // -------------------------------------------------------------------------

    /// @notice A signed liveness attestation from the Confidential TEE Oracle.
    /// @dev    The raw video is purged from enclave memory BEFORE this struct
    ///         is signed. Only the score, nonce, and the TEE-flavor-specific
    ///         quote survive.
    /// @param  nonce       Per-request nonce (prevents replay).
    /// @param  score       Liveness score in basis points (0..10000).
    /// @param  timestamp   Attestation issuance time (unix seconds).
    /// @param  teeFlavor   1 = AWS Nitro, 2 = Intel TDX, 3 = AMD SEV-SNP.
    ///                     Additional flavors registered via TEE registry.
    /// @param  teeQuote    Flavor-specific attestation blob (Nitro doc, TDX
    ///                     quote, or SEV-SNP report). Verifier picks parser
    ///                     by `teeFlavor`. See HumanKey ADR-0007 for the
    ///                     flavor deprecation policy.
    /// @param  signature   Oracle's signing-key signature over keccak256(
    ///                     abi.encode(nonce, score, timestamp, teeFlavor,
    ///                     keccak256(teeQuote))).
    struct LivenessAttestation {
        bytes32 nonce;
        uint16  score;
        uint64  timestamp;
        uint8   teeFlavor;
        bytes   teeQuote;
        bytes   signature;
    }

    // -------------------------------------------------------------------------
    // Session policy — the hash committed by `policyHash` in
    // IConspicuousUsageEvents.SessionIssued. The full struct lives off-chain
    // in Patronus / the dApp; only the hash is on-chain.
    // -------------------------------------------------------------------------

    /// @notice The full off-chain policy whose keccak256 hash is `policyHash`.
    ///         Defined here so cross-repo serializers agree on field order.
    /// @param  allowedSelectors 4-byte function selectors the session may call.
    /// @param  maxValueWei      Max ETH value per UserOp.
    /// @param  validUntil       Session expiry (unix seconds).
    /// @param  geoFenceHash     Optional geofence policy hash (0 = none).
    /// @param  parentSessionId  Parent session for F3 consent transitivity
    ///                          (bytes32(0) = root session).
    /// @param  requiredAal      NIST AAL minimum (1, 2, 3) needed at signing.
    struct SessionPolicy {
        bytes4[] allowedSelectors;
        uint256  maxValueWei;
        uint48   validUntil;
        bytes32  geoFenceHash;
        bytes32  parentSessionId;
        uint8    requiredAal;
    }

    // IMPLEMENTATION NOTES:
    // - Solidity struct field ORDER is part of the shared contract. Re-ordering
    //   changes the ABI encoding seen by signers and breaks cross-repo signature
    //   verification.
    // - `teeQuote` is intentionally `bytes` (not a sized hash) because each TEE
    //   flavor has its own quote format and length. Verifiers MUST dispatch on
    //   `teeFlavor` BEFORE parsing.
    // - `SessionPolicy.requiredAal` lets ERC-4337 validators enforce the F2
    //   (hardware-backed at Moderate+) and NIST AAL2/AAL3 (per 800-63B-4 Aug
    //   2025) requirements at the contract level.
}
