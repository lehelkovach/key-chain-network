# KeyChain Network Roadmap

## Vision

A minting authority for agent identity. Every agent gets a canonical UUID, a
readable handle, a key pair, and a certificate chain to a human-held root — so a
relying party can decide whether an agent is real and what it may do, offline,
from the credential the agent presents.

The first relying party is [IAC-Bus](https://github.com/lehelkovach/iac-bus).
KeyChain conforms to the bus's ACP v2 identity model rather than inventing its
own, and the bus can adopt it in stages without ever depending on it.

## M0 — Minting core (done)

- [x] ACP v2 identity grammar: `agent_uuid`, `agent:<brand>.<repo>.<ordinal>`,
      `<handle>@<medium>`, ordinal hierarchy with automatic child allocation.
- [x] Ed25519 key material, RFC 7638 thumbprints as key ids, OKP JWK encoding.
- [x] Identity certificates and offline chain-of-trust verification: signature
      coverage, capability attenuation, ordinal parenting, validity nesting,
      revocation, trusted-root termination.
- [x] Capability grammar with strict attenuation and per-role defaults aligned to
      the IAC-Bus surface.
- [x] Compact EdDSA JWS capability tokens, self-contained or authority-signed.
- [x] Parent-signed delegation, so the chain records real delegation.
- [x] Idempotent minting with the full ACP v2 conflict matrix plus key-binding
      conflicts.
- [x] Two custody modes, including bring-your-own public key so the private half
      never reaches the KeyChain host.
- [x] Private keys sealed at rest with AES-256-GCM under `KEYCHAIN_MASTER_KEY`.
- [x] Cascading revocation and a pollable revocation list.
- [x] SQLite storage mirroring the ACP v2 draft schema, plus Postgres DDL.
- [x] Flask HTTP surface with an ACP v2 compatible `POST /agents/register`.
- [x] CLI for bootstrap, minting, revocation and offline verification.
- [x] JSON schemas validated against real service output.
- [x] Test suite, live smoke script, systemd unit, CI.

## M1 — Operational hardening

- [ ] Trust root rotation: register a successor root, cross-sign, re-issue leaf
      certificates without changing any `agent_uuid`.
- [ ] Externally held roots: register a root by public key only, with the private
      key offline or in an HSM, so KeyChain can verify under it but not mint.
- [ ] Certificate renewal ahead of expiry, keeping the identity and key stable.
- [ ] Structured audit export and a `GET /revocations` delta feed with an ETag.
- [ ] Rate limits and per-caller quotas on the mint endpoints.
- [ ] Backup and restore procedure for the sealed database and master key.

## M2 — Relying party ergonomics

- [ ] `keychain-verify`: a dependency-light verifier package a relying party can
      vendor, with no storage or service code.
- [ ] Reference IAC-Bus patch implementing stages 2 and 3 of
      [the integration guide](docs/IAC_BUS_INTEGRATION.md), behind a flag.
- [ ] Language ports of the verifier, starting with TypeScript, so non-Python
      agents and relying parties can participate.
- [ ] Proof-of-possession challenge endpoint, for a relying party that wants to
      confirm an agent holds the key rather than just presents a token.

## M3 — The network

- [ ] Federation: accept chains from another KeyChain instance under a
      cross-signed root, with explicit per-peer capability ceilings.
- [ ] Postgres backend behind the store interface, for more than one instance.
- [ ] Human root of trust via
      [human-key-core](https://github.com/lehelkovach/human-key-core): a person's
      key signs the roots, so the top of every chain is a human.
- [ ] Delegation receipts: a signed record of who minted what, queryable as
      provenance the way IAC-Bus queries message provenance.

## M4 — Policy

- [ ] Declarative capability policy per role and namespace, versioned in the repo
      rather than encoded in defaults.
- [ ] Constrained delegation: parents restricted in what they may grant children
      beyond simple attenuation, for example by channel or repo path.
- [ ] Time-boxed and single-use capabilities.
- [ ] Optional OPA-compatible hook, matching the pattern the ACP v2 dev plan
      anticipates for the bus.

## Non-goals

- Becoming a message bus, a task scheduler, or a secrets manager.
- Blockchain or distributed-ledger trust.
- Sitting on the request hot path. Verification stays offline; if KeyChain is
  down, agents keep working with what they already hold.
