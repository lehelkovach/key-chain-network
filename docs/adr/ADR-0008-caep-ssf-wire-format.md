# ADR-0008 — CAEP / SSF Wire Format for Conspicuous Usage

**Status:** Proposed
**Date:** 2026-05-27
**Deciders:** Keychain protocol architecture
**Addresses:** Pivot P1; complements V9 (post-auth session theft) mitigations

## Context

The Conspicuous Usage event stream is the protocol's defining feature. Today, every enterprise SSO (Okta, Microsoft Entra, Google Cloud Identity, PingFederate, JumpCloud, OneLogin, Auth0) implements the **OpenID Continuous Access Evaluation Profile 1.0 (CAEP)** built on the **Shared Signals Framework (SSF)** to receive real-time security signals from identity providers. Events are delivered as **Security Event Tokens (SETs)** — signed JWTs per RFC 8417.

If Keychain emits its events only in a custom format, every receiver needs a custom integration. If Keychain *also* emits them in CAEP format, every CAEP receiver consumes Keychain telemetry **without writing any new code**.

This is a pure ecosystem-fit win.

## Decision

**Keychain emits Conspicuous Usage events in two parallel channels:**

1. **Native channel** — raw events on the Keychain Layer 1 BlockDAG, indexed by `pairwiseCommitment`. Highest fidelity.
2. **CAEP channel** — for each emitted event, also serialize a Security Event Token (SET) per OpenID CAEP 1.0 / SSF, signed by the user's pairwise DID's signing key (or by Patronus on the user's behalf), and POST to any subscribed receiver endpoint.

Mapping:

| Keychain event | CAEP event-type URI |
|---|---|
| `SessionIssued` | `https://schemas.openid.net/secevent/caep/event-type/session-established` |
| `SessionRevoked` | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` |
| `SessionUsed`, `AgentAction`, `StorageAccess` | `https://schemas.openid.net/secevent/caep/event-type/session-presented` |
| `DelegationGranted` | `https://schemas.openid.net/secevent/caep/event-type/token-claims-change` (scope changed) |
| `AnomalyDetected` (severity ≥ threshold) | `https://schemas.openid.net/secevent/caep/event-type/assurance-level-change` (downgrade) |
| `Minted`, `RecoveryInitiated`, `LineageRebound`, `InheritanceTick` | Not mapped to CAEP (HumanKey-specific); delivered only on the native channel + HumanKey webhooks |

### SET envelope

Standard RFC 8417 SET JWT:

```json
{
  "iss": "https://patronus.<user-pairwise-did>",
  "iat": 1714000000,
  "jti": "<event-id>",
  "aud": "<receiver-endpoint-url>",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-presented": {
      "subject": {
        "format": "opaque",
        "id": "<keychain-pairwise-commitment>"
      },
      "session_id": "<keychain-session-id>",
      "event_timestamp": 1714000000
    }
  }
}
```

Subject format is `opaque` because we never share the pairwise DID's full public form with arbitrary receivers — just the on-chain commitment.

### Subscription

Receivers subscribe per pairwise commitment with a standard SSF push-stream configuration. Patronus is the user's authoritative emitter; relying parties register their endpoints via a standard SSF discovery flow.

### Conformance

The CAEP profile we conform to: **OpenID CAEP 1.0** (finalized 2024). Forward-compatible with the SSF Push and Poll profiles.

## Consequences

**Positive:**
- Zero-integration consumption of Keychain telemetry by any CAEP-compliant SSO platform.
- Maps Keychain naturally onto Zero Trust architectures.
- Lets enterprises adopt Keychain incrementally — keep existing SSO, add Keychain as a CAEP transmitter, gain Conspicuous Usage for free.
- Plays well with NIST 800-63B-4 continuous-evaluation guidance.

**Negative:**
- Two channels means two emission paths; risk of drift. Mitigated by single-emitter pattern in `caep-emitter.ts` (the CAEP serializer reads from the same in-memory event).
- CAEP doesn't have native event types for HumanKey-specific concepts (mint, recovery, inheritance); those stay native-only. Acceptable.
- Receivers need to handle the `opaque` subject format and resolve identity through the pairwise commitment, not through a global identifier. Standards-permitted; some receivers may need configuration.

## Alternatives considered

- **Native channel only** — rejected (ecosystem fit too valuable to skip).
- **CAEP only, drop native channel** — rejected (CAEP doesn't cover all our event types).
- **Custom format with a separate CAEP bridge service** — rejected (additional moving piece; first-class CAEP support is simpler).
- **Webhook-only (no CAEP)** — rejected (receivers would still need custom integration; we'd be reinventing CAEP).

## Open questions

- Signing key for the SET — recommend the user's pairwise DID's key (signed by Patronus). Alternative: a single Keychain protocol key per emitter node (simpler but less attributable). Defer pick.
- Whether to also support the SSF Poll profile in addition to Push — recommend yes; defer implementation.
- HumanKey events not in the CAEP mapping — propose new CAEP event-type URIs under a Keychain namespace? Defer to a separate spec discussion.

## References

- `docs/05-conspicuous-usage.md` Appendix A
- `interfaces/ts/caep-emitter.ts`
- OpenID Continuous Access Evaluation Profile 1.0 (final).
- IETF RFC 8417 — Security Event Tokens.
- OpenID Shared Signals Framework.
