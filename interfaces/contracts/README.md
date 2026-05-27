# Keychain Solidity Interfaces

> **Interfaces only.** This pass intentionally ships no implementations.

## Toolchain expectations

When implementation work begins (not in this pass):

- **Compiler:** Solidity ^0.8.24.
- **Framework:** Foundry preferred (forge, anvil, cast). Hardhat acceptable. No framework files in this directory at v1 — interfaces compile standalone.
- **EVM target:** Paris (no PUSH0 dependency unless target chains support it). Base v1 supports Cancun; defer.
- **OpenZeppelin:** v5 patterns (`AccessControl`, `Initializable`, `UUPSUpgradeable`).
- **ERC-4337:** v0.7 EntryPoint. Use `eth-infinitism/account-abstraction` v0.7.x.

## Files in this directory

| File | Purpose |
|---|---|
| `events/IConspicuousUsageEvents.sol` | **SHARED with HumanKey** — canonical event taxonomy. |
| `SharedStructs.sol` | **SHARED with HumanKey** — cross-protocol Solidity structs. |
| `IKeychainAnchor.sol` | Layer 2 anchor (per-epoch Merkle commit + ZK pruning proof). |
| `IKeychainUpgradeGovernor.sol` | Web-of-Trust proxy upgrade governor (ADR-0002). |
| `IPairwiseDIDRegistry.sol` | Commitment-only registry; root DID never recoverable (ADR-0003). |
| `IEphemeralSessionKeyManager.sol` | ERC-4337 v0.7 session keys with ADR-0007 hardening (F7). |
| `IStorageNetGateway.sol` | Layer 3 access gateway; log-before-serve invariant. |

## What is NOT here

- No implementations (interfaces only).
- No tests (per scope decision; implementation pass adds them).
- No deployment scripts.
- No Foundry / Hardhat config (so interfaces compile under any toolchain).

## Verifying syntactically

```bash
# Foundry (when added):
forge build

# Standalone solc (works today):
solc --version  # require >= 0.8.24
solc --no-color interfaces/contracts/**/*.sol
```

## Modifying the SHARED files

The two files marked SHARED above (`events/IConspicuousUsageEvents.sol` and `SharedStructs.sol`) are pinned by the sibling HumanKey repo at this repo's commit SHA. Modifications require a coordinated update across both repos. See `.github/pull_request_template.md` for the checklist.
