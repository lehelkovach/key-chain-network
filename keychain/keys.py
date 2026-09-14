"""Ed25519 key material: generation, JWK encoding, signing, and key wrapping.

Design notes:

* Ed25519 only. One curve keeps certificate verification trivial for clients and
  removes algorithm-negotiation as an attack surface.
* Key identifiers are RFC 7638 JWK thumbprints, so any JOSE library computes the
  same ``kid`` from the same public key without asking KeyChain.
* Private keys that KeyChain must retain (trust roots, and agents minted with
  ``custody=keychain``) are sealed with AES-256-GCM under a key derived from
  ``KEYCHAIN_MASTER_KEY``. The agent's key identifier is bound in as additional
  authenticated data so a sealed blob cannot be moved between rows.
"""

import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import b64u_decode, b64u_encode, thumbprint
from .errors import ConfigurationError, SignatureError, ValidationError

ALGORITHM = "Ed25519"
JWS_ALGORITHM = "EdDSA"
KEY_TYPE = "OKP"
CURVE = "Ed25519"

WRAP_PREFIX_SEALED = "kcw1"
WRAP_PREFIX_PLAINTEXT = "kcw0"
_WRAP_INFO = b"key-chain-network/keywrap/v1"
_MASTER_KEY_ENV = "KEYCHAIN_MASTER_KEY"
_ALLOW_PLAINTEXT_ENV = "KEYCHAIN_ALLOW_PLAINTEXT_KEYS"


def generate_private_key():
    return Ed25519PrivateKey.generate()


def private_key_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_from_bytes(raw):
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise ValidationError("invalid Ed25519 private key") from exc


def public_key_from_bytes(raw):
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise ValidationError("invalid Ed25519 public key") from exc


def public_jwk(public_key):
    """Public key as an OKP JWK with its RFC 7638 thumbprint as ``kid``."""
    jwk = {
        "kty": KEY_TYPE,
        "crv": CURVE,
        "x": b64u_encode(public_key_bytes(public_key)),
    }
    jwk["kid"] = jwk_thumbprint(jwk)
    return jwk


def private_jwk(private_key):
    """Private key as an OKP JWK. Returned to callers exactly once, never stored."""
    jwk = public_jwk(private_key.public_key())
    jwk["d"] = b64u_encode(private_key_bytes(private_key))
    return jwk


def jwk_thumbprint(jwk):
    """RFC 7638 thumbprint over the required OKP members."""
    if not isinstance(jwk, dict):
        raise ValidationError("jwk must be an object")
    for member in ("kty", "crv", "x"):
        if not isinstance(jwk.get(member), str) or not jwk[member]:
            raise ValidationError("jwk is missing required member '%s'" % member)
    return thumbprint({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})


def load_public_jwk(jwk):
    """Validate an OKP JWK and return the ``cryptography`` public key."""
    if not isinstance(jwk, dict):
        raise ValidationError("jwk must be an object")
    if jwk.get("kty") != KEY_TYPE:
        raise ValidationError("jwk kty must be %s" % KEY_TYPE)
    if jwk.get("crv") != CURVE:
        raise ValidationError("jwk crv must be %s" % CURVE)
    raw = b64u_decode(jwk.get("x") or "")
    if len(raw) != 32:
        raise ValidationError("jwk x must decode to 32 bytes")
    declared_kid = jwk.get("kid")
    if declared_kid is not None and declared_kid != jwk_thumbprint(jwk):
        raise ValidationError("jwk kid does not match its thumbprint")
    return public_key_from_bytes(raw)


def load_private_jwk(jwk):
    if not isinstance(jwk, dict):
        raise ValidationError("jwk must be an object")
    raw = b64u_decode(jwk.get("d") or "")
    if len(raw) != 32:
        raise ValidationError("jwk d must decode to 32 bytes")
    private_key = private_key_from_bytes(raw)
    if jwk.get("x") and public_jwk(private_key.public_key())["x"] != jwk["x"]:
        raise ValidationError("jwk d and x describe different keys")
    return private_key


def key_id_for_jwk(jwk):
    return jwk_thumbprint(jwk)


def sign(private_key, payload):
    """Sign bytes, returning an unpadded base64url signature."""
    return b64u_encode(private_key.sign(payload))


def verify(public_key, signature, payload):
    """Verify a base64url signature, raising :class:`SignatureError` on failure."""
    try:
        public_key.verify(b64u_decode(signature), payload)
    except InvalidSignature as exc:
        raise SignatureError("signature verification failed") from exc
    return True


def is_valid_signature(public_key, signature, payload):
    try:
        return verify(public_key, signature, payload)
    except (SignatureError, ValidationError):
        return False


class KeyWrapper:
    """Seals private keys at rest with AES-256-GCM.

    ``master_key`` is a 32-byte secret; the per-record encryption key is derived
    from it with HKDF-SHA256 so the same master key can safely protect many
    records.
    """

    def __init__(self, master_key):
        if not isinstance(master_key, bytes) or len(master_key) < 32:
            raise ConfigurationError("master key must be at least 32 bytes")
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_WRAP_INFO,
        ).derive(master_key)

    @property
    def seals(self):
        return True

    def wrap(self, plaintext, aad):
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, aad.encode("utf-8"))
        return "%s.%s.%s" % (
            WRAP_PREFIX_SEALED,
            b64u_encode(nonce),
            b64u_encode(ciphertext),
        )

    def unwrap(self, sealed, aad):
        parts = sealed.split(".")
        if len(parts) != 3 or parts[0] != WRAP_PREFIX_SEALED:
            raise ValidationError("sealed key blob is malformed")
        nonce = b64u_decode(parts[1])
        ciphertext = b64u_decode(parts[2])
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext, aad.encode("utf-8"))
        except InvalidTag as exc:
            raise ValidationError(
                "sealed key blob failed authentication (wrong master key or aad)"
            ) from exc


class PlaintextKeyWrapper:
    """Development-only fallback that stores private keys unencrypted.

    Only reachable when ``KEYCHAIN_ALLOW_PLAINTEXT_KEYS`` is set, and the HTTP
    ``/health`` payload reports ``key_custody_sealed: false`` so an operator can
    see it from the outside.
    """

    @property
    def seals(self):
        return False

    def wrap(self, plaintext, aad):
        del aad
        return "%s.%s" % (WRAP_PREFIX_PLAINTEXT, b64u_encode(plaintext))

    def unwrap(self, sealed, aad):
        del aad
        parts = sealed.split(".")
        if len(parts) != 2 or parts[0] != WRAP_PREFIX_PLAINTEXT:
            raise ValidationError("plaintext key blob is malformed")
        return b64u_decode(parts[1])


def _decode_master_key(value):
    text = value.strip()
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raw = b64u_decode(text)
    if len(raw) < 32:
        raise ConfigurationError(
            "%s must decode to at least 32 bytes" % _MASTER_KEY_ENV
        )
    return raw


def key_wrapper_from_env(env=None):
    """Build the configured wrapper, refusing plaintext custody by default."""
    env = os.environ if env is None else env
    master_key = env.get(_MASTER_KEY_ENV, "").strip()
    if master_key:
        return KeyWrapper(_decode_master_key(master_key))
    if str(env.get(_ALLOW_PLAINTEXT_ENV, "")).strip().lower() in {"1", "true", "yes", "on"}:
        return PlaintextKeyWrapper()
    raise ConfigurationError(
        "%s is required to hold private keys; set %s=1 for local development only"
        % (_MASTER_KEY_ENV, _ALLOW_PLAINTEXT_ENV)
    )


def generate_master_key():
    """A fresh master key, hex-encoded for ``KEYCHAIN_MASTER_KEY``."""
    return os.urandom(32).hex()
