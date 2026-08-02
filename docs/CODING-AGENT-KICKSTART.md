# KeyChain 2.0 — Coding Agent Kickstart

Status: architecture consolidation before runtime  
Repository: `lehelkovach/key-chain-network`

## Mission

Build KeyChain-lite: an agent-safe grant wallet and lifecycle service that issues, attenuates, presents, verifies, and revokes bounded authority while keeping signing keys out of LLM context.

## Repository reality

- default `main` is a placeholder;
- substantive designs live only on `cursor/keychain-human-key-architecture-1092`;
- `AGENTS.md` is isolated on `cursor/setup-agents-md-ff68`;
- current TypeScript and Solidity artifacts are declarations/interfaces, not runtime;
- Patronus, BlockDAG, StorageNet, anchor, and governor designs are aspirational.

First create one clean architecture PR that combines the coordination instructions and useful design documents. Mark deferred systems explicitly. Do not claim interfaces are implemented.

## Boundaries

KeyChain owns:

- agent/workload key-provider abstraction;
- grant issuance, delegation, presentation, use accounting, and revocation;
- delegation-chain verification and monotonic attenuation;
- status/revocation resolution;
- conspicuous-use event publication;
- adapters to IAC and external credential/token systems.

KeyChain does not own message routing, task queues, execution, global consensus, human authenticator UX, or semantic authorization.

## MVP shape

Start as a library plus optional local service. Use ordinary durable storage. Reuse the IAC `CapabilityGrant` contract and canonicalization/signature decisions.

```text
packages/
  contracts/       # versioned grant/status interfaces and fixtures
  key-provider/    # local test provider plus production interface
  grants/          # issue/delegate/verify/use/revoke
  policy/          # exact resource/action/constraint matching
  adapters/iac/    # schema/envelope translation
  adapters/oauth/  # later token exchange/resource binding
services/
  status/          # optional revocation/status API
```

## Required grant semantics

- issuer, subject agent, audience, exact capabilities, canonical resources;
- `not_before`, `expires_at`, nonce, max uses, cost/risk limits;
- key confirmation and signature;
- parent grant digest and delegation depth;
- status reference/revocation epoch;
- explicit denials preserved across delegation.

Delegation must only narrow. Path and URI normalization happens before matching. A missing/unreachable status source fails closed for protected actions according to stated policy.

## Work packages

1. Consolidate branches and publish an honest implementation status matrix.
2. Import/freeze shared IAC contract fixtures; do not fork incompatible schemas.
3. Canonical bytes, digest, signer/verifier, and key-provider boundary.
4. Grant repository with issue/get/list/use/revoke and append-only audit events.
5. Delegation verifier with complete-chain attenuation and negative tests.
6. Status API and cache semantics with explicit fail-closed/fail-open classifications.
7. IAC adapter and two-agent demo.
8. Only after real integration: OAuth RAR/Token Exchange/DPoP adapter or Biscuit/UCAN evaluation.

## Security tests

- child cannot widen capability, resource, time, cost, use count, audience, or depth;
- revoked/expired parent invalidates descendants;
- agent cannot substitute its key or subject identifier;
- resource normalization cannot escape a path/prefix;
- replay and concurrent max-use consumption are deterministic;
- LLM/tool arguments never expose signing secrets;
- conspicuous-use events contain safe metadata, not credentials;
- unsupported proof/version/issuer fails closed.

## Definition of done

- human root grant is issued through a provider interface;
- supervisor delegates a narrower grant to a worker;
- worker presents proof and IAC verifies it for one exact action;
- revoke/expiry/replay/widening tests fail correctly;
- all state survives restart and concurrent use accounting is safe;
- public docs clearly separate live code from deferred network designs.

## Explicitly deferred

GHOSTDAG/BlockDAG, Ethereum anchoring, StorageNet, tokenomics, ZK identity, global decentralized discovery, custom consensus, on-chain governor, and cross-operator settlement.

