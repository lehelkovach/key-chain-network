"""Capability tokens: compact EdDSA JWS bearer credentials for minted agents.

The token is a standard three-part compact JWS
(``base64url(header).base64url(payload).base64url(signature)``) so an existing
JOSE library can consume it, with two issuing modes:

*self-contained* (default)
    The agent signs with its own key and the certificate chain travels in the
    ``kcc`` header member. A relying party such as IAC-Bus verifies the token
    with no network call and no shared secret -- it only needs the key
    identifier of a trust root it accepts. This is the mode that replaces a
    single shared ``BUS_API_TOKEN`` with per-agent, attenuated, expiring
    credentials.

*authority-signed*
    A trust root signs a token about an agent, and the relying party resolves
    ``kid`` through the KeyChain JWKS endpoint. Useful for service accounts and
    for clients that cannot hold a private key.
"""

import json
import uuid

from . import capabilities as caps
from . import certificates, keys
from .canonical import b64u_decode, b64u_encode, canonical_json, from_epoch, to_epoch, utcnow
from .errors import SignatureError, TrustError, ValidationError
from .protocol import PROTOCOL_VERSION

TOKEN_TYPE = "kc1-token"
DEFAULT_TTL_SECONDS = 3600
MAX_TTL_SECONDS = 30 * 24 * 3600

#: Size above which a token stops being comfortable in an ``Authorization``
#: header. An embedded chain costs roughly 1.4 KB per link, so a deep delegation
#: tree can produce a token that common proxy defaults (nginx allows 8 KB of
#: request headers in total) will reject. Issuance does not fail above this --
#: the token is still valid -- but callers are told the size so they can switch
#: to an authority-signed token or carry the chain out of band.
HEADER_SAFE_BYTES = 4096

#: Tolerance for clock skew between issuer and verifier, in seconds.
CLOCK_SKEW_SECONDS = 60


def _encode_segment(value):
    return b64u_encode(canonical_json(value))


def _decode_segment(segment, field):
    try:
        return json.loads(b64u_decode(segment).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValidationError("token %s is not valid JSON" % field) from exc


def _normalize_audience(audience):
    if audience is None:
        return []
    if isinstance(audience, str):
        audience = [audience]
    if not isinstance(audience, (list, tuple)):
        raise ValidationError("audience must be a string or list of strings")
    normalized = []
    for entry in audience:
        if not isinstance(entry, str) or not entry.strip():
            raise ValidationError("audience entries must be non-empty strings")
        normalized.append(entry.strip())
    return sorted(set(normalized))


def issue_token(
    signing_key,
    subject,
    capabilities,
    audience=None,
    ttl_seconds=DEFAULT_TTL_SECONDS,
    chain=None,
    issuer_ref=None,
    root_key_id=None,
    now=None,
    jti=None,
    extra_claims=None,
):
    """Mint a compact JWS capability token.

    ``subject`` is an agent certificate subject block. Pass ``chain`` (leaf to
    root) to produce a self-contained token; omit it for an authority-signed
    token that verifiers resolve through JWKS.
    """
    if not isinstance(subject, dict):
        raise ValidationError("subject must be an object")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
        raise ValidationError("ttl_seconds must be an integer")
    if ttl_seconds <= 0:
        raise ValidationError("ttl_seconds must be positive")
    if ttl_seconds > MAX_TTL_SECONDS:
        raise ValidationError("ttl_seconds must not exceed %d" % MAX_TTL_SECONDS)

    issued_at = now or utcnow()
    signer_jwk = keys.public_jwk(signing_key.public_key())
    header = {
        "alg": keys.JWS_ALGORITHM,
        "typ": TOKEN_TYPE,
        "kid": keys.key_id_for_jwk(signer_jwk),
    }
    if chain:
        leaf_key_id = ((chain[0].get("subject") or {}).get("key_id"))
        if leaf_key_id != header["kid"]:
            raise ValidationError(
                "self-contained token must be signed by the leaf certificate key"
            )
        header["kcc"] = list(chain)

    payload = {
        "kc_version": PROTOCOL_VERSION,
        "jti": jti or str(uuid.uuid4()),
        "iss": issuer_ref or subject.get("logical_handle"),
        "sub": subject.get("agent_uuid"),
        "handle": subject.get("logical_handle"),
        "role": subject.get("role"),
        "caps": caps.normalize_capabilities(capabilities),
        "iat": to_epoch(issued_at),
        "nbf": to_epoch(issued_at),
        "exp": to_epoch(issued_at) + ttl_seconds,
    }
    if subject.get("endpoint_handle"):
        payload["endpoint"] = subject["endpoint_handle"]
    audience = _normalize_audience(audience)
    if audience:
        payload["aud"] = audience
    if root_key_id:
        payload["root"] = root_key_id
    for key, value in (extra_claims or {}).items():
        if key in payload:
            raise ValidationError("extra claim %r would overwrite a reserved claim" % key)
        payload[key] = value

    signing_input = "%s.%s" % (_encode_segment(header), _encode_segment(payload))
    signature = keys.sign(signing_key, signing_input.encode("ascii"))
    return "%s.%s" % (signing_input, signature)


def decode(token):
    """Split a compact token into ``(header, payload, signature, signing_input)``.

    Performs no signature or expiry checks. Use only for introspection and for
    routing a token to the right verifier.
    """
    if not isinstance(token, str):
        raise ValidationError("token must be a string")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValidationError("token must have three dot-separated segments")
    header = _decode_segment(parts[0], "header")
    payload = _decode_segment(parts[1], "payload")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValidationError("token header and payload must be objects")
    return header, payload, parts[2], ("%s.%s" % (parts[0], parts[1])).encode("ascii")


class TokenVerification:
    """Outcome of :func:`verify_token`."""

    def __init__(self, valid, errors=None, payload=None, chain_verification=None):
        self.valid = valid
        self.errors = list(errors or [])
        self.payload = payload
        self.chain_verification = chain_verification

    @property
    def capabilities(self):
        return list((self.payload or {}).get("caps") or [])

    def to_dict(self):
        result = {
            "valid": self.valid,
            "errors": self.errors,
            "claims": self.payload,
        }
        if self.chain_verification is not None:
            result["chain"] = self.chain_verification.to_dict()
        return result

    def raise_for_status(self):
        if not self.valid:
            raise TrustError("token verification failed", details=self.errors)
        return self


def verify_token(
    token,
    trusted_root_key_ids=None,
    resolve_jwk=None,
    audience=None,
    now=None,
    is_revoked=None,
    required_capabilities=None,
):
    """Verify a capability token.

    For a self-contained token the embedded chain is verified against
    ``trusted_root_key_ids``. For an authority-signed token, ``resolve_jwk`` is
    called with the header ``kid`` and must return the signer's public JWK or
    ``None``.

    ``is_revoked`` receives a certificate and returns True when it is revoked. It
    only sees the embedded chain, so an authority-signed token carries no
    revocation evidence of its own; callers that can reach a KeyChain instance
    should also check the subject (:meth:`keychain.service.KeyChainService.verify_token`
    does).
    """
    errors = []
    now = now or utcnow()

    try:
        header, payload, signature, signing_input = decode(token)
    except ValidationError as exc:
        return TokenVerification(False, [str(exc)])

    if header.get("alg") != keys.JWS_ALGORITHM:
        errors.append("unsupported token alg %r" % header.get("alg"))
    if header.get("typ") != TOKEN_TYPE:
        errors.append("unsupported token typ %r" % header.get("typ"))
    if payload.get("kc_version") != PROTOCOL_VERSION:
        errors.append("unsupported token kc_version %r" % payload.get("kc_version"))

    chain_verification = None
    chain = header.get("kcc")
    signer_jwk = None
    if chain:
        if not isinstance(chain, list):
            errors.append("token kcc header must be a list of certificates")
        else:
            chain_verification = certificates.verify_chain(
                chain,
                trusted_root_key_ids or (),
                now=now,
                is_revoked=is_revoked,
            )
            if not chain_verification.valid:
                errors.extend(chain_verification.errors)
            leaf_subject = (chain[0].get("subject") or {}) if chain else {}
            signer_jwk = leaf_subject.get("public_key")
            if leaf_subject.get("agent_uuid") != payload.get("sub"):
                errors.append("token subject does not match the leaf certificate")
            if leaf_subject.get("logical_handle") != payload.get("handle"):
                errors.append("token handle does not match the leaf certificate")
            if not caps.is_attenuation(
                payload.get("caps") or [], chain[0].get("capabilities") or []
            ):
                errors.append(
                    "token claims capabilities beyond its leaf certificate"
                )
    else:
        if resolve_jwk is None:
            errors.append(
                "token has no embedded chain and no key resolver was supplied"
            )
        else:
            signer_jwk = resolve_jwk(header.get("kid"))
            if signer_jwk is None:
                errors.append("unknown token signing key %r" % header.get("kid"))

    if signer_jwk is not None:
        try:
            keys.verify(keys.load_public_jwk(signer_jwk), signature, signing_input)
        except (SignatureError, ValidationError) as exc:
            errors.append("token signature is invalid: %s" % exc)

    expires_at = payload.get("exp")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        errors.append("token exp claim is missing or not an integer")
    elif from_epoch(expires_at).timestamp() < now.timestamp() - CLOCK_SKEW_SECONDS:
        errors.append("token is expired")

    not_before = payload.get("nbf")
    if isinstance(not_before, int) and not isinstance(not_before, bool):
        if from_epoch(not_before).timestamp() > now.timestamp() + CLOCK_SKEW_SECONDS:
            errors.append("token is not yet valid")

    if audience is not None:
        accepted = _normalize_audience(audience)
        claimed = _normalize_audience(payload.get("aud"))
        if not claimed:
            errors.append("token has no aud claim but an audience was required")
        elif not set(claimed) & set(accepted):
            errors.append(
                "token audience %s does not include %s"
                % (", ".join(claimed), ", ".join(accepted))
            )

    if required_capabilities:
        granted = payload.get("caps") or []
        missing = [
            capability
            for capability in caps.normalize_capabilities(required_capabilities)
            if not caps.allows(granted, capability)
        ]
        if missing:
            errors.append(
                "token is missing required capabilities: %s" % ", ".join(missing)
            )

    return TokenVerification(
        valid=not errors,
        errors=errors,
        payload=payload,
        chain_verification=chain_verification,
    )
