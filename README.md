# key-chain-network

KeyChain mints identities for agents.

Give it a brand, a repo and a role, and it returns an `agent_uuid`, a readable
handle like `agent:cursor.iac-bus.0-1`, an Ed25519 key pair, and a certificate
chain proving the identity was issued by someone you trust. Relying parties such
as [IAC-Bus](https://github.com/lehelkovach/iac-bus) can then authorize an agent
from a token alone, with no shared secret and no callback to KeyChain.

The identity model is deliberately the one IAC-Bus already specifies in
[ACP v2](https://github.com/lehelkovach/iac-bus/blob/master/docs/ACP_PROTOCOL_V2.md)
section 2, so KeyChain is a drop-in minting authority rather than a parallel
scheme. `POST /agents/register` implements the ACP v2 registration contract
field for field, including its conflict matrix.

- [What KeyChain gives you](#what-keychain-gives-you)
- [Quick start](#quick-start)
- [The identity it mints](#the-identity-it-mints)
- [The chain of trust](#the-chain-of-trust)
- [Capability tokens](#capability-tokens)
- [HTTP API](#http-api)
- [CLI](#cli)
- [Configuration](#configuration)
- [Security model](#security-model)
- [Development](#development)
- [Documentation](#documentation)

## What KeyChain gives you

| Problem | What KeyChain does |
| --- | --- |
| Agents share one bus token, so every agent can do everything | Each agent gets its own key and an attenuated capability set |
| A leaked token cannot be withdrawn without rotating everyone | Revoke one identity; its subtree goes with it |
| Agent identity is a string anyone can claim | A handle is bound to a public key by a signed certificate |
| "Who spawned this agent?" is a convention, not a fact | The parent signs the child's certificate; the chain is the answer |
| The bus must call an identity service on every request | Tokens carry their own chain, so verification is offline |
| Two coordinating repos disagree on an agent's id | ACP v2 handles, plus optional reproducible UUIDv5 derivation |

## Quick start

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt -r requirements-dev.txt

# One master key seals every private key KeyChain retains.
export KEYCHAIN_MASTER_KEY="$(./venv/bin/python keychain_cli.py gen-master-key \
  | ./venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["KEYCHAIN_MASTER_KEY"])')"
export KEYCHAIN_API_TOKEN=devtoken
export KEYCHAIN_AUTO_BOOTSTRAP_ROOT=1

./venv/bin/python server.py
```

In another terminal:

```bash
KEYCHAIN_URL=http://127.0.0.1:8102 KEYCHAIN_API_TOKEN=devtoken \
  bash scripts/keychain_smoke.sh
./venv/bin/pytest -q
```

The smoke script walks the whole path an IAC-Bus deployment takes: bootstrap
discovery, mint an orchestrator, delegate a worker beneath it, register through
the ACP v2 endpoint, issue and verify a token, then revoke and prove the token
stops working.

Mint your first agent:

```bash
curl -sS -X POST http://127.0.0.1:8102/agents/mint \
  -H 'Authorization: Bearer devtoken' -H 'Content-Type: application/json' \
  -d '{"brand":"cursor","repo_locale":"iac-bus","role":"orchestrator","medium":"ide"}'
```

## The identity it mints

Three layers, matching ACP v2:

```
agent_uuid       9f3c1a2e-...             canonical, immutable, what the bus stores
logical_handle   agent:cursor.iac-bus.0-1  readable, encodes brand, repo and position
endpoint_handle  agent:cursor.iac-bus.0-1@web   the handle qualified by transport
```

The ordinal path is the agent tree. `0` is the master of a repo namespace, `0-1`
is its second child, `0-4-8` a grandchild. Omit `ordinal_path` on a mint and
KeyChain allocates the next free child of the parent you named, so a spawning
orchestrator never has to guess an index or race a sibling.

Minting is idempotent on the logical handle. Re-minting returns `200` with the
original `agent_uuid` and certificate; anything that would change the identity
behind a handle is a `409` with a specific `conflict_code`
(`HANDLE_PARENT_MISMATCH`, `HANDLE_ROLE_MISMATCH`, `HANDLE_KEY_MISMATCH`,
`HANDLE_IDENTITY_MISMATCH`, `HANDLE_ROOT_MISMATCH`, `HANDLE_REVOKED`). A handle
is bound to one key for life.

## The chain of trust

This is the "key chain" the repo is named for. Each certificate is signed by the
identity that issued it, up to a self-signed root:

```
root:lehel-root                     (human-held, capabilities: *)
└── agent:cursor.iac-bus.0          orchestrator: bus.*, agent.mint, task.assign
    ├── agent:cursor.iac-bus.0-0    worker: bus.post, bus.read
    └── agent:cursor.iac-bus.0-1    reviewer: bus.post, bus.read, task.review
```

When KeyChain holds the parent's key, the parent signs its children, so the
chain records real delegation rather than a flat list of root-signed
certificates. Verification enforces, at every link:

- the signature, over the canonical JSON of the whole certificate minus the
  signature, so no field can be edited or added after issuance;
- capability attenuation, so a child can never claim more than its issuer holds;
- ordinal parenting inside a namespace, so `0-1` must be signed by `0`;
- validity nesting, so a certificate never outlives its issuer;
- revocation, and that the chain terminates in a root you trust.

`verify_chain` collects every problem instead of stopping at the first, because
when a token is rejected you want the whole story at once.

## Capability tokens

A token is a compact EdDSA JWS. The default form is *self-contained*: the agent
signs with its own key and the certificate chain rides in the `kcc` header. A
relying party verifies it with one pinned root key id, no network call and no
shared secret.

```python
from keychain import tokens

result = tokens.verify_token(
    presented_token,
    trusted_root_key_ids=[PINNED_ROOT_KEY_ID],
    audience="iac-bus",
    required_capabilities=["bus.post"],
)
if not result.valid:
    return 403, {"error": "Unauthorized", "details": result.errors}

agent_uuid = result.payload["sub"]       # what IAC-Bus stores on every message
handle = result.payload["handle"]        # agent:cursor.iac-bus.0-1
```

Agents minted with the default `custody=agent` hold their own private key, so
they sign their own tokens and KeyChain never sees the key at all. Agents minted
with `custody=keychain` let KeyChain sign for them, which is what enables
parent-signed delegation and server-side token issuance.

## HTTP API

Everything except `/health` and the two `.well-known` documents requires
`Authorization: Bearer $KEYCHAIN_API_TOKEN`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness, version, counts, and whether private keys are sealed |
| `GET` | `/metrics` | Health plus the non-secret configuration |
| `GET` | `/.well-known/keychain/roots.json` | Trust anchors to pin, with their certificates |
| `GET` | `/.well-known/keychain/jwks.json` | Root public keys for authority-signed tokens |
| `POST` | `/trust/roots` | Create a trust root |
| `GET` | `/trust/roots` | List trust roots |
| `POST` | `/trust/roots/<root_id>/default` | Move the default root |
| `POST` | `/agents/mint` | Mint an identity (KeyChain-native, `medium` optional) |
| `POST` | `/agents/register` | Mint an identity (ACP v2 contract, `medium` required) |
| `POST` | `/agents/heartbeat` | Update endpoint liveness |
| `GET` | `/agents` | List and filter identities |
| `GET` | `/agents/<uuid or handle>` | Describe one identity, its endpoints and children |
| `GET` | `/agents/<uuid or handle>/chain` | Just the certificate chain |
| `POST` | `/agents/<uuid or handle>/revoke` | Revoke, cascading to descendants by default |
| `POST` | `/verify/certificate` | Verify a certificate or a full chain |
| `POST` | `/tokens/issue` | Issue a capability token |
| `POST` | `/tokens/verify` | Verify a token (`403` when invalid) |
| `GET` | `/revocations` | Revocation list, filterable by `since` |
| `GET` | `/audit` | Mint and revocation audit trail |

Request and response shapes are specified in [`schemas/`](schemas/) and covered
by tests that validate real service output.

## CLI

`keychain_cli.py` talks to the SQLite database directly, so it works before a
trust root exists and with no service running.

```bash
python3 keychain_cli.py gen-master-key
python3 keychain_cli.py init-root --name lehel-root
python3 keychain_cli.py mint --brand cursor --repo iac-bus --role orchestrator \
  --out orchestrator.identity.json
python3 keychain_cli.py mint --brand cursor --repo iac-bus --role worker \
  --parent agent:cursor.iac-bus.0

# An agent that holds its own key signs its own token, offline.
python3 keychain_cli.py token --private-key orchestrator.identity.json \
  --audience iac-bus

# A relying party verifies with nothing but a pinned root key id.
python3 keychain_cli.py verify-token --token "$KC_TOKEN" --audience iac-bus \
  --trusted-root-key-id "$ROOT_KEY_ID"

python3 keychain_cli.py revoke agent:cursor.iac-bus.0 --reason "key leaked"
```

## Configuration

See [`.env.example`](.env.example) for the annotated list. The ones that matter:

| Variable | Default | Notes |
| --- | --- | --- |
| `KEYCHAIN_MASTER_KEY` | *(none)* | 32 bytes, hex or base64url. Required to hold private keys |
| `KEYCHAIN_ALLOW_PLAINTEXT_KEYS` | `0` | Local development escape hatch; surfaced on `/health` |
| `KEYCHAIN_API_TOKEN` | *(none)* | Bearer token. Empty disables auth |
| `KEYCHAIN_DB_PATH` | `keychain.db` | SQLite path, or `:memory:` |
| `KEYCHAIN_PORT` | `8102` | Chosen to sit beside IAC-Bus on `8101` |
| `KEYCHAIN_AUTO_BOOTSTRAP_ROOT` | `0` | Create a default root on first start |
| `KEYCHAIN_UUID_MODE` | `random` | `derived` makes `agent_uuid` reproducible across replicas |
| `KEYCHAIN_ISSUER_MODE` | `auto` | `auto`, `root`, or `parent` |
| `KEYCHAIN_DEFAULT_AUDIENCE` | `iac-bus` | Default token audience |

## Security model

- **Ed25519 only.** One curve, no algorithm negotiation.
- **Key ids are RFC 7638 thumbprints**, so any JOSE library derives the same
  `kid` from the same public key.
- **Private keys KeyChain retains are sealed** with AES-256-GCM under a key
  derived from `KEYCHAIN_MASTER_KEY`, with the key id bound in as additional
  authenticated data so a sealed blob cannot be moved between records. Without a
  master key the service refuses to start.
- **Default custody is `agent`.** The private key is returned once and not
  stored, so compromising KeyChain does not let an attacker impersonate agents
  that hold their own keys.
- **Authority only narrows downward**, enforced at mint, at chain verification,
  and at token issuance.
- **Revocation cascades** by default, drops any retained private key, and
  deactivates endpoints. A compromised orchestrator's children are not left with
  working credentials.
- **Signatures cover canonical JSON** with floats rejected rather than rounded,
  so the bytes that were signed are always reproducible.

## Development

```bash
./venv/bin/pytest -q                              # full suite
./venv/bin/pytest tests/test_acp_v2_compat.py -q  # ACP v2 conformance only
KEYCHAIN_URL=... KEYCHAIN_API_TOKEN=... bash scripts/keychain_smoke.sh
```

Tests run against an in-memory store with a fixed key wrapper, so they need no
environment and touch no files. CI runs the suite on Python 3.10 and 3.12, plus
the live smoke and a CLI bootstrap that verifies a token offline.

Layout:

```
keychain/identity.py       handle grammar and ordinal paths
keychain/keys.py           Ed25519, JWK, thumbprints, key sealing
keychain/capabilities.py   capability grammar and attenuation
keychain/certificates.py   issuance and chain verification
keychain/tokens.py         compact EdDSA JWS capability tokens
keychain/store.py          SQLite persistence
keychain/service.py        the minting authority
server.py                  Flask HTTP surface
keychain_cli.py            offline CLI
```

## Documentation

- [`docs/KEYCHAIN_PROTOCOL.md`](docs/KEYCHAIN_PROTOCOL.md) — wire format for
  certificates and tokens, verification algorithm, conflict matrix.
- [`docs/IAC_BUS_INTEGRATION.md`](docs/IAC_BUS_INTEGRATION.md) — how to wire
  this into IAC-Bus, staged so nothing breaks.
- [`docs/sql/KEYCHAIN_SCHEMA.sql`](docs/sql/KEYCHAIN_SCHEMA.sql) — Postgres DDL.
- [`ROADMAP.md`](ROADMAP.md) — what is built and what comes next.
- [`AGENTS.md`](AGENTS.md) — instructions for agents working on this repo.
