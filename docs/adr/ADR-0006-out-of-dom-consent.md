# ADR-0006 — Out-of-DOM Consent Channel

**Status:** Proposed
**Date:** 2026-05-27
**Deciders:** Keychain protocol architecture
**Addresses:** F1; mitigates V4 (WebAuthn API hijacking / prompt spoofing) and V5 (XSS-driven passkey substitution)

## Context

Two pieces of 2025 security research broke a common assumption about consent UX:

1. **DEF CON 33 (Allthenticate, Aug 2025)** demonstrated **WebAuthn API hijacking** against synced passkeys. The attacker spoofs the OS-level authentication prompt in real time during an active phishing session. The user clicks "approve" on what looks exactly like their normal passkey prompt; the session is hijacked.

2. **Scott Helme (2025–2026)** — "XSS Is Deadly for Passkeys: The Hidden Risk of Attestation None". A page-level adversary (XSS) proxies `navigator.credentials.create()` and substitutes the attacker's passkey at registration time. The user sees their normal Authenticator UI; the resulting passkey works only for the attacker. Persistent, invisible.

Both attacks share a root cause: **the consent UI lives in or near the page DOM**, and a DOM-level attacker can either intercept it (V5) or spoof it (V4).

Any Patronus consent UI that runs in the browser page is downstream of these attacks. We need a stronger primitive.

## Decision

**The Patronus consent ceremony runs in an out-of-DOM channel. The dApp page may request consent; the dApp page may never render, proxy, or observe the consent dialog.**

Concrete per-form-factor implementation:

| Patronus form-factor | Out-of-DOM channel |
|---|---|
| Native mobile app (iOS/Android) | OS-level system overlay or in-app prompt; the browser cannot reach this surface |
| Native desktop app (macOS/Windows/Linux) | OS-level toast / panel reachable only via OS notification subsystem |
| Hardware token (FIDO2-style companion) | Physical button press, separate display |
| TEE-backed companion device | Bluetooth-paired device with its own screen |

Implementation rules:

1. The dApp page initiates by calling `requestConsentOutOfDom(intent)` via a Patronus WebExtension API, a `postMessage` to a Patronus origin, or a registered URL scheme.
2. Patronus receives the request, evaluates risk, and **renders the consent dialog in its own UI surface**.
3. The page receives only a yes/no result and a signature reference — never the dialog content, never the user input.
4. If the dApp page attempts to render an imitation of the dialog (detected by Patronus heuristic or user report), Patronus emits `AnomalyDetected("consent-channel-violation")` and refuses to proceed.
5. The browser-extension Patronus (Pivot P3) is **deferred to v2**. In v1, the dApp must talk to a native Patronus instance.

## Consequences

**Positive:**
- DEF CON 33-class prompt spoofing is structurally impossible — the attacker cannot render Patronus's UI from inside the page.
- XSS passkey substitution does not apply — Patronus owns the create-credential ceremony in its own process.
- Aligns Patronus with the FIDO/W3C model where authenticators are out-of-band devices.

**Negative:**
- Friction: the user must have a Patronus install, not just a browser.
- Adoption barrier for dApps that want "just-a-button" integration. Partly mitigated by clear SDK; fully mitigated only by P3 (browser-extension Patronus) in v2.
- Cross-app coordination (deep links / URL schemes) is OS-dependent and adds engineering surface.

## Alternatives considered

- **In-page Patronus iframe sandbox** — rejected. Sandboxed iframe is still rendered by the page; a sufficiently sophisticated attacker can overlay it.
- **WebAuthn-only consent** — rejected. WebAuthn itself is what these attacks defeat (V4, V5).
- **Browser-vendor cooperation** (custom secure UI per browser) — rejected as v1 dependency. Possible v3 path if browsers ship Patronus-like primitives.

## Open questions

- Browser-extension Patronus (P3) — deferred to v2 by user decision; revisit if XSS resistance can be made acceptable inside an extension.
- Deep-link vs. WebSocket vs. local HTTP server for desktop dApp ↔ Patronus communication — implementation detail; defer.
- Whether to require the user to set a Patronus PIN per high-risk action — usability vs. security trade-off; recommend opt-in.

## References

- `docs/04-patronus-guardian.md` §4
- `docs/07-threat-model.md` V4, V5
- DEF CON 33 — Allthenticate "WebAuthn API Hijacking" presentation (Aug 2025).
- Scott Helme — "XSS Is Deadly for Passkeys: The Hidden Risk of Attestation None" (2025–2026).
