# Wiring KeyChain into IAC-Bus

[IAC-Bus](https://github.com/lehelkovach/iac-bus) states plainly in its
`AGENTS.md` that KeyChain is not a dependency, and its ladder tracker puts
KeyChain out of scope. That is the right call for the bus, and this document does
not ask you to change it.

The direction of the dependency runs the other way. KeyChain is built to satisfy
the identity model the bus already specifies, so the bus can adopt it when and if
it wants to, one stage at a time, with each stage useful on its own and none of
them breaking a bus that has not adopted anything.

- [Where KeyChain fits](#where-keychain-fits)
- [Stage 0: mint identities, change nothing](#stage-0-mint-identities-change-nothing)
- [Stage 1: KeyChain behind /agents/register](#stage-1-keychain-behind-agentsregister)
- [Stage 2: per-agent bus tokens](#stage-2-per-agent-bus-tokens)
- [Stage 3: capability enforcement per route](#stage-3-capability-enforcement-per-route)
- [Stage 4: revocation](#stage-4-revocation)
- [Deployment alongside IAC-Bus](#deployment-alongside-iac-bus)
- [What KeyChain deliberately does not do](#what-keychain-deliberately-does-not-do)

## Where KeyChain fits

The bus's ACP v2 plan needs an agent identity registry (rung **L2**: agent UUID
registry and heartbeat). KeyChain is that registry, plus the key material the
draft does not cover:

| ACP v2 concern | Where it lives |
| --- | --- |
| `agent_uuid`, logical handle, endpoint handle | KeyChain mints, the bus stores |
| Registration idempotency and conflict codes | KeyChain, contract for contract |
| Heartbeat and presence | Either; the bus is closer to the traffic |
| Message envelope, channels, routing, history | IAC-Bus, untouched |
| Task state, locks, provenance | IAC-Bus, untouched |
| Proving an agent is who it claims | KeyChain certificates |
| Deciding what an agent may do | KeyChain capabilities, enforced by the bus |

The bus keeps every routing and coordination concern. KeyChain answers exactly
two questions: *is this agent real*, and *what is it allowed to do*.

## Stage 0: mint identities, change nothing

Run KeyChain next to the bus and mint identities from it. The bus never learns
KeyChain exists; agents simply start using handles that are backed by keys.

```bash
export KEYCHAIN_MASTER_KEY="$(python3 keychain_cli.py gen-master-key \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["KEYCHAIN_MASTER_KEY"])')"
python3 keychain_cli.py init-root --name lehel-root

# The repo's master agent. custody=keychain lets it sign its own children.
python3 keychain_cli.py mint --brand cursor --repo iac-bus --role orchestrator \
  --custody keychain

# Each worker the orchestrator spawns, with its ordinal allocated for it.
python3 keychain_cli.py mint --brand cursor --repo iac-bus --role worker \
  --parent agent:cursor.iac-bus.0 --out worker.identity.json
```

The handle in `worker.identity.json` goes straight into the bus's existing
`AGENT_ID` environment variable:

```bash
AGENT_ID=agent:cursor.iac-bus.0-0@web
```

You now have a real answer to "which agent posted this, and who spawned it",
recorded in a signed chain rather than in a naming convention. Value delivered,
zero bus changes.

## Stage 1: KeyChain behind /agents/register

When the bus implements ACP v2 `POST /agents/register`, it can proxy to KeyChain
instead of writing its own registry. KeyChain's `/agents/register` implements the
section 4.1 contract — the same request fields, the same normalization, the same
`201`/`200`/`400`/`404`/`409` outcomes and the same conflict codes — and adds its
own material under a `keychain` member that an ACP v2 client can ignore.

```python
# iac-bus: server.py
import os
import requests

KEYCHAIN_URL = os.environ.get("KEYCHAIN_URL", "")
KEYCHAIN_API_TOKEN = os.environ.get("KEYCHAIN_API_TOKEN", "")


@app.post("/agents/register")
def register_agent():
    if not KEYCHAIN_URL:
        return _register_locally(request.get_json(silent=True) or {})

    upstream = requests.post(
        "%s/agents/register" % KEYCHAIN_URL,
        json=request.get_json(silent=True) or {},
        headers={"Authorization": "Bearer %s" % KEYCHAIN_API_TOKEN},
        timeout=10,
    )
    payload = upstream.json()
    if upstream.status_code in (200, 201):
        # Mirror the identity locally so message history can join against it
        # without a KeyChain round trip on every read.
        _upsert_agent_row(payload)
    return jsonify(payload), upstream.status_code
```

Keeping the `KEYCHAIN_URL` guard means the bus still runs standalone, which
matters for its own test suite and for anyone who has not deployed KeyChain.

## Stage 2: per-agent bus tokens

Today the bus authenticates with one shared `BUS_API_TOKEN`: every agent that has
it can do everything, and rotating it rotates it for everyone. Stage 2 replaces
that with a per-agent token the bus verifies offline.

The bus needs one new setting — the trust root key id to pin — and no network
call:

```bash
BUS_TRUSTED_ROOT_KEY_ID=OMZNgEgPhnR-BgkvG7Vfw-7aVXjBlOqIZwS8u2uFeXM
```

Get it from `GET /.well-known/keychain/roots.json`, or from the output of
`keychain_cli.py init-root`.

```python
# iac-bus: replaces _require_auth()
from keychain import tokens

BUS_TRUSTED_ROOT_KEY_ID = os.environ.get("BUS_TRUSTED_ROOT_KEY_ID", "")
BUS_AUDIENCE = os.environ.get("BUS_AUDIENCE", "iac-bus")


def _require_auth():
    presented = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    # Keep the shared token working while agents migrate.
    if BUS_API_TOKEN and presented == BUS_API_TOKEN:
        g.agent_uuid = None
        g.capabilities = ["*"]
        return None

    if not BUS_TRUSTED_ROOT_KEY_ID:
        return jsonify({"error": "Unauthorized"}), 401

    result = tokens.verify_token(
        presented,
        trusted_root_key_ids=[BUS_TRUSTED_ROOT_KEY_ID],
        audience=BUS_AUDIENCE,
    )
    if not result.valid:
        logger.info("rejected token: %s", "; ".join(result.errors))
        return jsonify({"error": "Unauthorized"}), 401

    # Identity the rest of the request can rely on, proven cryptographically.
    g.agent_uuid = result.payload["sub"]
    g.agent_handle = result.payload["handle"]
    g.capabilities = result.payload.get("caps", [])
    return None
```

`keychain.tokens` and `keychain.certificates` depend only on `cryptography`, so
the bus can vendor those two modules rather than take a service dependency, and
verification still needs no call to KeyChain.

Agents get their token from the identity document they were minted with:

```bash
KC_TOKEN="$(python3 keychain_cli.py token --private-key worker.identity.json \
  --audience iac-bus --ttl-seconds 3600 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"

curl -sS -X POST "$BUS_URL/bus/messages" \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"channel":"ops","agent":"agent:cursor.iac-bus.0-0@web","type":"progress",
       "message":"started"}'
```

Two things the bus gets for free here. The `agent` field in an ACP envelope no
longer has to be trusted: the bus can compare it to `g.agent_handle` and reject a
mismatch, which closes off one agent posting as another. And because the token
carries `sub`, the durable history requirement in ACP v2 section 6 — every
message stored against a canonical `agent_uuid` — is satisfied from the
credential itself rather than from a client-supplied field.

### One sizing caveat

A self-contained token carries its certificate chain, at roughly 1.4 KB per link:
about 3.3 KB for a root-signed agent, about 6 KB four levels deep. nginx allows
8 KB of request headers by default, so a deep tree can produce a token a proxy
rejects. `POST /tokens/issue` reports `token_bytes` and a `header_safe` flag so
this is visible before it bites. If your agent tree gets deep, either mint the
deeper agents with `"issuer": "root"` — which keeps every chain two links long at
the cost of no longer recording delegation in the chain — or use authority-signed
tokens, which stay under a kilobyte at any depth. Numbers and the third option
are in [the protocol doc](KEYCHAIN_PROTOCOL.md#token-size).

## Stage 3: capability enforcement per route

With `g.capabilities` populated, the bus's authority model (ACP v2 section 5.3 —
orchestrators assign and cancel, children execute) becomes enforcement instead of
convention.

```python
from functools import wraps
from keychain import capabilities as caps


def requires(capability):
    def decorate(view):
        @wraps(view)
        def guarded(*args, **kwargs):
            if not caps.allows(getattr(g, "capabilities", []), capability):
                return jsonify({
                    "error": "Forbidden",
                    "required_capability": capability,
                }), 403
            return view(*args, **kwargs)
        return guarded
    return decorate


@app.post("/bus/messages")
@requires("bus.post")
def post_message():
    ...


@app.post("/queues/<queue>/claim")
@requires("bus.claim")
def claim(queue):
    ...


@app.post("/tasks/<task_uuid>/assign")
@requires("task.assign")   # orchestrators hold this; workers do not
def assign(task_uuid):
    ...
```

The capabilities KeyChain mints by role are chosen to line up with this surface:
`bus.post`, `bus.read`, `bus.claim`, `bus.ack`, `lock.acquire`, `task.assign`,
`task.review`, `agent.mint`. A worker's default set has no `task.assign`, so a
worker cannot assign work to a sibling even if it constructs the request
correctly.

## Stage 4: revocation

Revoke an identity in KeyChain and its subtree goes with it:

```bash
curl -sS -X POST "$KEYCHAIN_URL/agents/agent:cursor.iac-bus.0-0/revoke" \
  -H "Authorization: Bearer $KEYCHAIN_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"leaked key","cascade":true}'
```

Offline verification cannot see a revocation, so a token already issued stays
valid until it expires. That is the trade for not calling KeyChain on every
request, and there are two ways to close it, which combine well:

1. **Short TTLs.** One hour by default. An agent refreshes its token from its own
   private key with no KeyChain call, so a short TTL costs nothing operationally.
2. **A polled deny list.** The bus polls `GET /revocations?since=<timestamp>` and
   keeps revoked key ids in memory:

```python
def _load_revocations():
    response = requests.get(
        "%s/revocations" % KEYCHAIN_URL,
        params={"since": _last_poll_timestamp()},
        headers={"Authorization": "Bearer %s" % KEYCHAIN_API_TOKEN},
        timeout=10,
    )
    for entry in response.json()["revocations"]:
        REVOKED_KEY_IDS.add(entry["key_id"])


# In _require_auth(), after a successful verify:
chain = tokens.decode(presented)[0].get("kcc") or []
if any((cert.get("subject") or {}).get("key_id") in REVOKED_KEY_IDS for cert in chain):
    return jsonify({"error": "Unauthorized"}), 401
```

The bus stays available if KeyChain is down: a stale deny list still rejects
everything it knew about, and short TTLs bound the rest.

## Deployment alongside IAC-Bus

KeyChain defaults to port **8102**, beside the bus on 8101, and ships the same
shape of deployment artefacts (`wsgi.py` for gunicorn,
`systemd/key-chain-network.service`), so it drops into the same VM and the same
deploy scripts.

```bash
# On the OCI VM
sudo mkdir -p /opt/key-chain-network /var/lib/key-chain-network /etc/key-chain-network
sudo install -o root -g root -m 0600 /dev/stdin /etc/key-chain-network/keychain.env <<'ENV'
KEYCHAIN_MASTER_KEY=<32 bytes hex>
KEYCHAIN_API_TOKEN=<bus-to-keychain token>
KEYCHAIN_DEFAULT_AUDIENCE=iac-bus
ENV
sudo cp systemd/key-chain-network.service /etc/systemd/system/
sudo systemctl enable --now key-chain-network
curl -fsS http://127.0.0.1:8102/health
```

Secrets, by name only:

| Purpose | Name |
| --- | --- |
| Seals private keys at rest | `KEYCHAIN_MASTER_KEY` |
| Bus-to-KeyChain admin calls | `KEYCHAIN_API_TOKEN` |
| Root the bus pins | `BUS_TRUSTED_ROOT_KEY_ID` (public, not a secret) |

Bind KeyChain to `127.0.0.1` and let only the bus and your deploy tooling reach
it. Nothing in an agent's normal path needs to: agents mint tokens from the key
they already hold, and the bus verifies them offline.

Back up `KEYCHAIN_MASTER_KEY` separately from the database. The database without
the master key is inert; either one alone is useless, which is the point.

## What KeyChain deliberately does not do

- **It is not a bus.** No messages, channels, queues or task state.
- **It is not on the hot path.** Verification is offline by design; if KeyChain is
  down, agents keep working with the tokens and keys they hold.
- **It does not require adoption.** Every stage above is opt-in, and the bus runs
  unchanged without any of them.
- **It does not federate yet.** One instance, one or more trust roots. Cross-org
  trust and root rotation are on the [roadmap](../ROADMAP.md).
