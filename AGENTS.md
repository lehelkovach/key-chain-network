# Agent instructions (key-chain-network)

KeyChain mints identities for agents: an `agent_uuid`, an ACP v2 logical handle,
an Ed25519 key pair, and a certificate chain up to a human-held trust root.
It exists to serve [iac-bus](https://github.com/lehelkovach/iac-bus); the
dependency runs one way only.

## Ingest order

1. This file (`AGENTS.md`)
2. `README.md` — what the service is and how to run it
3. `docs/KEYCHAIN_PROTOCOL.md` — wire format and verification rules
4. `docs/IAC_BUS_INTEGRATION.md` — when touching anything the bus consumes
5. `ROADMAP.md` — what is built and what is next

## Hard constraints

- **KeyChain serves IAC-Bus, not the reverse.** Never add an iac-bus import,
  HTTP call or runtime dependency here. IAC-Bus's own `AGENTS.md` states KeyChain
  is not a dependency of the bus; respect that in both directions.
- **Never widen authority.** Capabilities may only narrow going down a chain.
  If a change makes a child able to do something its issuer cannot, it is wrong.
- **A handle is bound to one key for life.** Re-minting is idempotent; anything
  that would rebind an identity is a `409` with a specific `conflict_code`, never
  a silent overwrite.
- **Never log or return private key material** beyond the single documented
  return at mint time with `custody=agent`.
- **Do not weaken `KEYCHAIN_MASTER_KEY` handling.** Plaintext custody stays
  behind an explicit opt-in and stays visible on `/health`.
- **Signatures cover the whole document.** Do not add fields that are excluded
  from the signing payload.
- Keep diffs scoped to the task.

## Default local loop

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt -r requirements-dev.txt

export KEYCHAIN_MASTER_KEY="$(./venv/bin/python keychain_cli.py gen-master-key \
  | ./venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["KEYCHAIN_MASTER_KEY"])')"
KEYCHAIN_API_TOKEN=devtoken KEYCHAIN_AUTO_BOOTSTRAP_ROOT=1 ./venv/bin/python server.py

# other terminal:
KEYCHAIN_URL=http://127.0.0.1:8102 KEYCHAIN_API_TOKEN=devtoken \
  bash scripts/keychain_smoke.sh
./venv/bin/pytest -q
```

Acceptance: smoke all green, `pytest -q` all green.

## Test expectations

- Every behavioural change needs a test. The suite runs on an in-memory store
  with a fixed key wrapper: no environment, no files, no network.
- `tests/test_acp_v2_compat.py` is a conformance suite against
  `iac-bus/docs/ACP_PROTOCOL_V2.md`. If a change makes it fail, the change is
  wrong unless the spec itself moved — and then say so in the commit message.
- `tests/test_schemas.py` validates real service output against `schemas/`. Update
  the schema and the code together; a schema that drifts is worse than none.
- Security properties get negative tests, not comments: tamper with the document,
  escalate the capability, forge the parent, and assert the rejection.

## Where to look

| Need | Location |
| --- | --- |
| Handle grammar, ordinal paths | `keychain/identity.py` |
| Ed25519, JWK, thumbprints, key sealing | `keychain/keys.py` |
| Capability grammar and attenuation | `keychain/capabilities.py` |
| Certificate issuance and chain rules | `keychain/certificates.py` |
| Capability tokens | `keychain/tokens.py` |
| Persistence | `keychain/store.py`, `docs/sql/KEYCHAIN_SCHEMA.sql` |
| Minting, conflicts, revocation | `keychain/service.py` |
| HTTP surface | `server.py` |
| Bootstrap and offline verification | `keychain_cli.py` |
| Wire format | `docs/KEYCHAIN_PROTOCOL.md`, `schemas/` |
| Bus integration | `docs/IAC_BUS_INTEGRATION.md` |

## Branch and version

- Feature branches: `cursor/<name>-<suffix>`, PR into `main`.
- Version source: `VERSION` plus `version.py`, surfaced on `/health`.
- `PROTOCOL_VERSION` in `version.py` is the `kc1` on the wire. Bump it only for a
  breaking format change, and only together with the schemas, the verification
  code and `docs/KEYCHAIN_PROTOCOL.md`.

## Secrets (names only)

| Purpose | Name |
| --- | --- |
| Seals private keys at rest | `KEYCHAIN_MASTER_KEY` |
| API bearer token | `KEYCHAIN_API_TOKEN` |
| Deploy | `KEYCHAIN_PROD_HOST`, `KEYCHAIN_PROD_USER`, `KEYCHAIN_PROD_KEY` |

Never print secret values; record required names only.

## Working rules

- Prove changes with `pytest -q` and the smoke script before claiming done.
- If blocked on missing secrets or hosts, report the blocker; do not fake it.
- Update `ROADMAP.md` when a milestone item lands.
