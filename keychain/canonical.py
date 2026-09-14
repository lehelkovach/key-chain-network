"""Deterministic JSON serialization and base64url helpers.

Signatures cover bytes, so producer and verifier must agree on exactly one
serialization of a claim set. We use the RFC 8785 (JCS) subset that our
documents actually need: object keys sorted by code point, no insignificant
whitespace, and no floating point numbers at all. Floats are rejected rather
than rounded so an unrepresentable value can never silently change the bytes
that were signed.
"""

import base64
import datetime
import hashlib
import json

from .errors import ValidationError


def b64u_encode(raw):
    """Base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(value):
    """Decode unpadded base64url text back to bytes."""
    if not isinstance(value, str):
        raise ValidationError("base64url value must be a string")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise ValidationError("value is not valid base64url: %s" % exc) from exc


def sha256(raw):
    return hashlib.sha256(raw).digest()


def _check_canonicalizable(value, path="$"):
    if isinstance(value, float):
        raise ValidationError("floats are not canonicalizable at %s" % path)
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError("object keys must be strings at %s" % path)
            _check_canonicalizable(item, "%s.%s" % (path, key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_canonicalizable(item, "%s[%d]" % (path, index))
    elif not isinstance(value, (str, int, bool, type(None))):
        raise ValidationError(
            "unsupported type %s at %s" % (type(value).__name__, path)
        )


def canonical_json(value):
    """Serialize ``value`` to the canonical byte string used for signing."""
    _check_canonicalizable(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def thumbprint(value):
    """Stable base64url SHA-256 digest of a canonicalized JSON value."""
    return b64u_encode(sha256(canonical_json(value)))


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def to_iso8601(moment):
    """Render an aware datetime as a second-precision Zulu timestamp."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    moment = moment.astimezone(datetime.timezone.utc).replace(microsecond=0)
    return moment.isoformat().replace("+00:00", "Z")


def from_iso8601(value):
    """Parse a Zulu or offset timestamp into an aware datetime."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError("invalid ISO-8601 timestamp: %s" % value) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def to_epoch(moment):
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return int(moment.timestamp())


def from_epoch(seconds):
    if seconds is None:
        return None
    return datetime.datetime.fromtimestamp(int(seconds), datetime.timezone.utc)
