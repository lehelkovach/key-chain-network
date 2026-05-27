# key-chain-network

> **Keychain Protocol** — a Consent-Mediated Identity Bus and Dynamic Identity Firewall.
> Sister repo: [`lehelkovach/human-key-core`](https://github.com/lehelkovach/human-key-core).
> Status: **design pass in progress** on branch `cursor/keychain-human-key-architecture-1092`. This README is rewritten with full content during phase E6.

## Quick map

- `docs/` — protocol design documents and ADRs.
- `interfaces/contracts/` — Solidity ^0.8.24 interface declarations (no bodies in this pass).
- `interfaces/ts/` — TypeScript declarations for off-chain components.
- `diagrams/` — Mermaid diagrams referenced from the docs.
- `interfaces/contracts/events/IConspicuousUsageEvents.sol` — **canonical event taxonomy** shared with HumanKey.
- `interfaces/contracts/SharedStructs.sol` — **shared Solidity structs** (Notary / Liveness / SessionPolicy).
- `interfaces/ts/shared-types.ts` — **shared TypeScript types**.

The three "shared" files above are the cross-repo contract. They must not be modified without coordinating with the HumanKey repo.

## License

MIT — see `LICENSE`.
