# KeyChain Protocol (kc1)

Wire format and verification rules for KeyChain identity certificates and
capability tokens. Written so a relying party can be implemented from this
document plus an Ed25519 library, in any language.

Protocol version: `kc1`. Machine-readable shapes live in [`../schemas/`](../schemas/).

- [1. Canonicalization](#1-canonicalization)
- [2. Keys and key identifiers](#2-keys-and-key-identifiers)
- [3. Identity model](#3-identity-model)
- [4. Capabilities](#4-capabilities)
- [5. Identity certificates](#5-identity-certificates)
- [6. Chain verification](#6-chain-verification)
- [7. Capability tokens](#7-capability-tokens)
- [8. Minting semantics](#8-minting-semantics)
- [9. Revocation](#9-revocation)
- [10. Deviations from the ACP v2 draft](#10-deviations-from-the-acp-v2-draft)

## 1. Canonicalization

Signatures cover bytes, so producer and verifier must agree on one serialization.
KeyChain uses the RFC 8785 (JCS) subset its documents need:

- object members sorted by Unicode code point;
- no whitespace between tokens;
- UTF-8 output, non-ASCII not escaped;
- no floating point numbers anywhere. A float is rejected, not rounded, so an
  unrepresentable value can never silently change the signed bytes.

Base64url is used without padding throughout. Timestamps are second-precision
UTC in `YYYY-MM-DDTHH:MM:SSZ`.

## 2. Keys and key identifiers

Ed25519 only. Public keys are OKP JWKs:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "ShQ1fvNKviHPyGXYcVhyDvQ_uktveDajKic6bCV-Jq0",
  "kid": "ihGtQFUE3tJfClH7L6luiqochxO-9c6bim_JaQQV8S8"
}
```

`kid` is the RFC 7638 thumbprint: base64url SHA-256 of the canonical JSON of
`{"crv","kty","x"}`. It is always 43 characters. Any JOSE library derives the
same value, so a verifier can confirm a declared `kid` rather than trusting it,
and KeyChain rejects a JWK whose `kid` does not match its own thumbprint.

Signature algorithm identifier is `EdDSA`, matching RFC 8037.

## 3. Identity model

Identical to
[ACP v2 section 2](https://github.com/lehelkovach/iac-bus/blob/master/docs/ACP_PROTOCOL_V2.md).

| Layer | Format | Example |
| --- | --- | --- |
| Canonical | UUID, immutable | `9f3c1a2e-6b71-4f0d-8c2a-1d5e7b9a3c40` |
| Logical handle | `agent:<brand>.<repo-locale>.<ordinal-path>` | `agent:cursor.iac-bus.0-1` |
| Endpoint handle | `<logical-handle>@<medium>` | `agent:cursor.iac-bus.0-1@web` |

```
ordinal-path    ^([0-9]+)(-[0-9]+)*$
logical-handle  ^agent:[a-z0-9_-]+\.[a-z0-9_.-]+\.[0-9]+(-[0-9]+)*$
medium          web | slack | ide | api | automation | other
```

Additional rules KeyChain enforces on top of the regexes:

- No leading zeros in an ordinal segment: `0-01` and `0-1` would otherwise be two
  handles for the same position.
- Ordinal depth is capped at 12.
- `brand`, `repo_locale`, `role` and `medium` are trimmed and lowercased;
  `ordinal_path` keeps its shape after validation.
- `repo_locale` may contain dots, so parsing takes `brand` from the first
  separator and `ordinal_path` from the last. That is unambiguous because an
  ordinal path never contains a dot: `agent:cursor.repo.x.y.0-4-8` parses as
  brand `cursor`, repo locale `repo.x.y`, ordinal path `0-4-8`.

`agent_uuid` allocation has two modes. `random` is UUIDv4, as ACP v2 specifies.
`derived` is UUIDv5 over `<trust-root-key-id>|<logical-handle>` in the namespace
`6f0f2b8a-2f6a-5c4e-9b1d-8a3c5f9e1d70`, which lets independent KeyChain replicas
sharing a trust root mint the same `agent_uuid` for the same handle without
coordinating.

## 4. Capabilities

A capability is a dot-separated lowercase path: `bus.post`, `lock.acquire`,
`agent.mint`. A grant may end in `.*` to cover a subtree, and the bare `*` grants
everything. Capability lists are normalized: lowercased, de-duplicated, sorted,
and collapsed to `["*"]` if the wildcard is present.

```
capability  ^(\*|[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?)$
```

Role defaults as minted by KeyChain:

| Role | Capabilities |
| --- | --- |
| `orchestrator`, `master` | `agent.mint`, `bus.ack`, `bus.claim`, `bus.post`, `bus.read`, `lock.acquire`, `task.assign` |
| `worker` | `bus.ack`, `bus.claim`, `bus.post`, `bus.read`, `lock.acquire` |
| `reviewer` | `bus.post`, `bus.read`, `task.review` |
| `observer` | `bus.read` |
| `service` | `bus.post`, `bus.read` |
| anything else | `bus.post`, `bus.read` |

Trust roots hold `*`. Any other role slug is accepted so downstream projects can
add their own; it gets the minimal default.

**Attenuation** is the load-bearing rule: a capability set may only narrow going
down a chain. It is enforced three times — when minting a certificate, when
verifying each link of a chain, and when issuing a token — so a verifier reaches
the same conclusion wherever it stops.

## 5. Identity certificates

```json
{
  "kc_version": "kc1",
  "cert_type": "agent",
  "cert_id": "3f9a1c77-0b2e-4a51-9d8f-6c4b21e5a7d0",
  "subject": {
    "agent_uuid": "9f3c1a2e-6b71-4f0d-8c2a-1d5e7b9a3c40",
    "logical_handle": "agent:cursor.iac-bus.0-1",
    "brand": "cursor",
    "repo_locale": "iac-bus",
    "ordinal_path": "0-1",
    "role": "worker",
    "parent_agent_uuid": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
    "key_id": "ihGtQFUE3tJfClH7L6luiqochxO-9c6bim_JaQQV8S8",
    "public_key": { "kty": "OKP", "crv": "Ed25519", "x": "...", "kid": "..." }
  },
  "issuer": {
    "cert_id": "5c1d0e2f-...",
    "key_id": "OMZNgEgPhnR-BgkvG7Vfw-7aVXjBlOqIZwS8u2uFeXM",
    "subject_ref": "agent:cursor.iac-bus.0",
    "self_signed": false
  },
  "capabilities": ["bus.post", "bus.read"],
  "issued_at": "2026-09-14T17:16:09Z",
  "expires_at": "2026-12-13T17:16:09Z",
  "signature": {
    "alg": "EdDSA",
    "key_id": "OMZNgEgPhnR-BgkvG7Vfw-7aVXjBlOqIZwS8u2uFeXM",
    "value": "base64url-ed25519-signature"
  }
}
```

`cert_type` is `agent` or `root`. A root certificate's subject is
`{root_id, name, key_id, public_key}` and its `issuer` has `self_signed: true`
with a null `cert_id`.

The signature covers the canonical JSON of the entire document with the
`signature` member removed. Nothing is excluded, so an unrecognised field cannot
be smuggled in: adding one breaks the signature. Verifiers must therefore reject
an unknown `kc_version` rather than ignore unknown members.

`issuer.cert_id` identifies the issuing certificate, not just the issuing key, so
chain reconstruction stays unambiguous when one key has signed several
certificates over its life.

A certificate is never issued with an expiry later than its issuer's; a longer
requested TTL is clamped.

## 6. Chain verification

Input: a chain ordered leaf first, self-signed root last, and a set of trusted
root key ids. Optionally a revocation predicate; omit it for pure offline
verification.

For every certificate:

1. `kc_version` is `kc1` and `cert_type` is known.
2. Not expired and not future-dated, allowing 60 seconds of clock skew.
3. Not revoked, if a predicate was supplied.
4. Its signature verifies against the next certificate's
   `subject.public_key` (the root verifies against its own).

For every link between a certificate and its issuer:

5. `issuer.key_id` equals the issuer's `subject.key_id`, and `issuer.cert_id`,
   when present, equals the issuer's `cert_id`.
6. The certificate does not expire later than its issuer.
7. Its capabilities are covered by the issuer's.
8. When both are agent certificates in the same `(brand, repo_locale)`
   namespace, the subject's ordinal path is a direct child of the issuer's, and a
   declared `parent_agent_uuid` matches the issuing agent. Across namespaces no
   ordinal relationship is required: an orchestrator in one repo may legitimately
   mint the master agent of another.

Finally:

9. The last certificate is a self-signed root whose `subject.key_id` is trusted.
10. Chain length is at most 16.

All failures are collected; verification returns every problem rather than the
first. On success the caller gets the leaf subject, the leaf capability set, the
root key id, and the chain length.

## 7. Capability tokens

A compact JWS: `base64url(header) "." base64url(payload) "." base64url(signature)`,
signature computed over the ASCII bytes of the first two segments joined by a dot.

```json
// header
{
  "alg": "EdDSA",
  "typ": "kc1-token",
  "kid": "ihGtQFUE3tJfClH7L6luiqochxO-9c6bim_JaQQV8S8",
  "kcc": [ /* certificate chain, leaf first, root last */ ]
}
// payload
{
  "kc_version": "kc1",
  "jti": "7c2f1e90-...",
  "iss": "agent:cursor.iac-bus.0-1",
  "sub": "9f3c1a2e-6b71-4f0d-8c2a-1d5e7b9a3c40",
  "handle": "agent:cursor.iac-bus.0-1",
  "endpoint": "agent:cursor.iac-bus.0-1@web",
  "role": "worker",
  "caps": ["bus.post", "bus.read"],
  "aud": ["iac-bus"],
  "root": "OMZNgEgPhnR-BgkvG7Vfw-7aVXjBlOqIZwS8u2uFeXM",
  "iat": 1789406169,
  "nbf": 1789406169,
  "exp": 1789409769
}
```

Two modes:

**Self-contained** (`kcc` present). Signed by the agent's own key; `kid` must
equal the leaf certificate's `subject.key_id`. Verified with nothing but a pinned
root key id. This is the mode to use with IAC-Bus.

**Authority-signed** (`kcc` absent). Signed by a trust root about an agent. The
verifier resolves `kid` through `/.well-known/keychain/jwks.json`. Useful for
service accounts and clients that cannot hold a private key. Because there is no
embedded chain there is no embedded revocation evidence, so a verifier that can
reach KeyChain should also check the subject.

Verification steps:

1. `alg` is `EdDSA`, `typ` is `kc1-token`, `kc_version` is `kc1`.
2. Self-contained: verify `kcc` as a chain (section 6), then confirm the leaf
   subject's `agent_uuid` and `logical_handle` match `sub` and `handle`, and that
   `caps` is covered by the leaf certificate's capabilities. Authority-signed:
   resolve `kid` to a public key.
3. Verify the signature over the signing input.
4. `exp` is present and in the future, and `nbf`, if present, is in the past,
   allowing 60 seconds of skew.
5. If the verifier requires an audience, `aud` must intersect it.
6. If the verifier requires capabilities, each must be covered by `caps`.

Default TTL is 3600 seconds; the protocol maximum is 30 days and a deployment can
lower it with `KEYCHAIN_MAX_TOKEN_TTL_SECONDS`.

### Token size

A self-contained token carries its whole chain, which costs roughly 1.4 KB per
link:

| Chain length | Self-contained | Authority-signed |
| --- | --- | --- |
| 2 (root → agent) | ~3.3 KB | ~0.8 KB |
| 3 | ~4.7 KB | ~0.8 KB |
| 4 | ~6.1 KB | ~0.8 KB |
| 5 | ~7.5 KB | ~0.8 KB |

nginx allows 8 KB of request headers in total by default, so a deep delegation
tree can produce a token a proxy will reject in an `Authorization` header.
`POST /tokens/issue` therefore reports `token_bytes` and a `header_safe` flag
(the threshold is 4096 bytes) and logs a warning above it. The token is still
valid — the flag is advice. Three ways to stay under a header limit:

- keep delegation trees shallow, or mint with `issuer: root` so the chain is two
  links regardless of tree depth;
- use an authority-signed token, which stays under a kilobyte at any depth;
- carry the chain out of band and present a token without `kcc`.

## 8. Minting semantics

`POST /agents/mint` and `POST /agents/register` share one implementation.
`/agents/register` additionally requires `medium` and returns the ACP v2 response
shape; `/agents/mint` defaults `medium` to `api` and returns the fuller identity
document.

Resolution order:

1. Normalize the request. Every validation problem in the body is reported
   together, not one at a time.
2. Resolve the trust root (`root`, else the instance default, else auto-bootstrap
   if configured).
3. Resolve the parent from `parent_agent_uuid` and/or `parent_handle`. A revoked
   parent cannot mint.
4. Resolve the ordinal path: use the one given, or allocate the next free child
   index under the parent, or `0` when there is no parent. A non-master ordinal
   with no parent is a `400`.
5. If the derived logical handle already exists, apply the conflict matrix below
   and return the existing identity on a match, adding an endpoint row for a new
   medium or session.
6. Otherwise choose the issuer, attenuate the requested capabilities against it,
   generate or accept a key, issue the certificate, and store everything.

### Conflict matrix

Rows 1 to 7 are the ACP v2 `/agents/register` matrix; the rest are KeyChain
additions covering key material.

| Scenario | Status | Behaviour |
| --- | --- | --- |
| First registration for a handle | `201` | Create the identity and its endpoint |
| Same handle, same identity, same medium and session | `200` | Return the existing identity |
| Same handle, same identity, new medium or session | `200` | Reuse the UUID, add an endpoint |
| Same handle, different `parent_agent_uuid` | `409` | `HANDLE_PARENT_MISMATCH` |
| Same handle, different brand/repo/ordinal derivation | `409` | `HANDLE_IDENTITY_MISMATCH` |
| Non-master ordinal with no parent | `400` | Reject the hierarchy |
| `parent_agent_uuid` does not resolve | `404` | `parent agent not found` |
| Same handle, different role | `409` | `HANDLE_ROLE_MISMATCH` |
| Same handle, different submitted public key | `409` | `HANDLE_KEY_MISMATCH` |
| Same public key, different handle | `409` | `HANDLE_KEY_MISMATCH` |
| Same handle, different trust root | `409` | `HANDLE_ROOT_MISMATCH` |
| Handle previously revoked | `409` | `HANDLE_REVOKED` |
| Requested capabilities exceed the issuer's | `400` | Name the undelegatable capabilities |

Conflict responses carry `conflict_code` and, where relevant,
`existing_agent_uuid`.

### Issuer selection

| `issuer` | Behaviour |
| --- | --- |
| `auto` (default) | The parent signs when KeyChain holds its private key; otherwise the trust root signs |
| `root` | The trust root signs |
| `parent` | The parent must sign; `409 key_not_in_custody` if its key is not held |

### Custody

| `custody` | Private key |
| --- | --- |
| `agent` (default) | Returned once in the mint response, never stored. KeyChain cannot sign for this agent |
| `keychain` | Sealed at rest so KeyChain can sign delegated certificates and self-contained tokens |

Supplying `public_key` in the mint request keeps the private key entirely off the
KeyChain host: the agent generates its own key and only ever sends the public
half.

## 9. Revocation

Revoking an identity marks it `revoked`, records it in the revocation list keyed
by both certificate id and public key id, deactivates its endpoints, and drops
any private key KeyChain held for it. By default it cascades to every descendant,
because a compromised parent may have minted children whose certificates chain
through it.

A revoked handle cannot be re-minted. Revocation is recorded, so a verifier with
access to KeyChain rejects both the chain and any token already issued; an offline
verifier holding only a pinned root key will accept a previously issued token
until it expires, which is why token TTLs are short by default.

`GET /revocations?since=<timestamp>` is the list a relying party polls to keep a
local deny list.

## 10. Deviations from the ACP v2 draft

KeyChain follows the ACP v2 draft except where the draft is internally
inconsistent or silent:

1. **`agent_endpoints.endpoint_handle` is not unique.** The draft marks it unique
   while also keying endpoints on `(agent_uuid, medium, session_id)`. Those cannot
   both hold: two sessions of one agent on one medium derive the same
   `<logical-handle>@<medium>`. KeyChain keeps the composite key and indexes the
   handle without a uniqueness constraint.
2. **`role` participates in the conflict matrix.** The draft's idempotency row
   lists role among the fields that must match but has no conflict code for it;
   KeyChain returns `HANDLE_ROLE_MISMATCH`.
3. **Ordinal segments may not have leading zeros**, and depth is capped. The
   draft's regex permits `0-01` and unbounded depth.
4. **`agent_uuid` may be a UUIDv5.** The draft says UUIDv4; the derived mode is
   opt-in and still a valid UUID.
5. **Capabilities, key material and certificates are additions.** They live in
   `keychain`-namespaced response members so an ACP v2 client can ignore them.
