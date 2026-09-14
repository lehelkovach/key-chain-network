"""Canonical serialization, Ed25519 handling, and key sealing."""

import pytest

from keychain import keys
from keychain.canonical import (
    b64u_decode,
    b64u_encode,
    canonical_json,
    from_iso8601,
    to_iso8601,
    utcnow,
)
from keychain.errors import ConfigurationError, SignatureError, ValidationError


class TestCanonicalJson:
    def test_key_order_does_not_change_the_bytes(self):
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_no_insignificant_whitespace(self):
        assert canonical_json({"a": [1, 2]}) == b'{"a":[1,2]}'

    def test_non_ascii_is_not_escaped(self):
        assert canonical_json({"name": "Lehel"}) == b'{"name":"Lehel"}'
        assert "ü" in canonical_json({"n": "ü"}).decode("utf-8")

    def test_floats_are_rejected_rather_than_rounded(self):
        with pytest.raises(ValidationError):
            canonical_json({"ttl": 1.5})

    def test_unsupported_types_are_rejected(self):
        with pytest.raises(ValidationError):
            canonical_json({"when": utcnow()})

    def test_base64url_round_trip_without_padding(self):
        raw = bytes(range(10))
        encoded = b64u_encode(raw)
        assert "=" not in encoded
        assert b64u_decode(encoded) == raw

    def test_timestamps_round_trip_as_zulu(self):
        moment = utcnow()
        rendered = to_iso8601(moment)
        assert rendered.endswith("Z")
        assert from_iso8601(rendered) == moment

    def test_invalid_timestamp_is_rejected(self):
        with pytest.raises(ValidationError):
            from_iso8601("yesterday")


class TestKeys:
    def test_public_jwk_shape(self):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert len(b64u_decode(jwk["x"])) == 32
        assert jwk["kid"] == keys.jwk_thumbprint(jwk)

    def test_thumbprint_ignores_extra_members(self):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        decorated = dict(jwk, use="sig", alg="EdDSA")
        assert keys.jwk_thumbprint(decorated) == jwk["kid"]

    def test_thumbprint_requires_the_core_members(self):
        with pytest.raises(ValidationError):
            keys.jwk_thumbprint({"kty": "OKP", "crv": "Ed25519"})

    def test_private_jwk_round_trip(self):
        private_key = keys.generate_private_key()
        jwk = keys.private_jwk(private_key)
        restored = keys.load_private_jwk(jwk)
        assert keys.private_key_bytes(restored) == keys.private_key_bytes(private_key)

    def test_load_public_jwk_rejects_a_mismatched_kid(self):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        with pytest.raises(ValidationError):
            keys.load_public_jwk(dict(jwk, kid="not-the-thumbprint"))

    def test_load_public_jwk_rejects_other_curves(self):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        with pytest.raises(ValidationError):
            keys.load_public_jwk(dict(jwk, crv="X25519", kid=None))

    def test_load_private_jwk_rejects_inconsistent_halves(self):
        first = keys.private_jwk(keys.generate_private_key())
        second = keys.public_jwk(keys.generate_private_key().public_key())
        with pytest.raises(ValidationError):
            keys.load_private_jwk(dict(first, x=second["x"]))

    def test_sign_and_verify(self):
        private_key = keys.generate_private_key()
        signature = keys.sign(private_key, b"payload")
        assert keys.verify(private_key.public_key(), signature, b"payload")

    def test_verify_rejects_a_tampered_payload(self):
        private_key = keys.generate_private_key()
        signature = keys.sign(private_key, b"payload")
        with pytest.raises(SignatureError):
            keys.verify(private_key.public_key(), signature, b"payload!")

    def test_verify_rejects_another_key(self):
        signature = keys.sign(keys.generate_private_key(), b"payload")
        other = keys.generate_private_key().public_key()
        assert keys.is_valid_signature(other, signature, b"payload") is False


class TestKeyWrapping:
    def test_seal_and_open(self, key_wrapper):
        secret = keys.private_key_bytes(keys.generate_private_key())
        sealed = key_wrapper.wrap(secret, aad="kid-1")
        assert sealed.startswith(keys.WRAP_PREFIX_SEALED)
        assert secret not in b64u_decode(sealed.split(".")[2])
        assert key_wrapper.unwrap(sealed, aad="kid-1") == secret

    def test_sealed_blob_is_bound_to_its_key_id(self, key_wrapper):
        sealed = key_wrapper.wrap(b"secret", aad="kid-1")
        with pytest.raises(ValidationError):
            key_wrapper.unwrap(sealed, aad="kid-2")

    def test_nonce_is_fresh_per_call(self, key_wrapper):
        assert key_wrapper.wrap(b"secret", aad="k") != key_wrapper.wrap(b"secret", aad="k")

    def test_wrong_master_key_cannot_open(self, key_wrapper):
        sealed = key_wrapper.wrap(b"secret", aad="k")
        with pytest.raises(ValidationError):
            keys.KeyWrapper(b"\xff" * 32).unwrap(sealed, aad="k")

    def test_short_master_key_is_refused(self):
        with pytest.raises(ConfigurationError):
            keys.KeyWrapper(b"too-short")

    def test_malformed_blob_is_refused(self, key_wrapper):
        with pytest.raises(ValidationError):
            key_wrapper.unwrap("kcw1.only-two-parts", aad="k")

    def test_plaintext_wrapper_round_trips_and_declares_itself(self):
        wrapper = keys.PlaintextKeyWrapper()
        assert wrapper.seals is False
        assert wrapper.unwrap(wrapper.wrap(b"secret", aad="k"), aad="k") == b"secret"


class TestKeyWrapperFromEnv:
    def test_hex_master_key_is_accepted(self):
        wrapper = keys.key_wrapper_from_env({"KEYCHAIN_MASTER_KEY": "aa" * 32})
        assert wrapper.seals is True

    def test_base64url_master_key_is_accepted(self):
        wrapper = keys.key_wrapper_from_env(
            {"KEYCHAIN_MASTER_KEY": b64u_encode(bytes(range(32)))}
        )
        assert wrapper.seals is True

    def test_generated_master_key_is_usable(self):
        wrapper = keys.key_wrapper_from_env(
            {"KEYCHAIN_MASTER_KEY": keys.generate_master_key()}
        )
        assert wrapper.seals is True

    def test_missing_master_key_refuses_to_start(self):
        with pytest.raises(ConfigurationError):
            keys.key_wrapper_from_env({})

    def test_plaintext_custody_requires_an_explicit_opt_in(self):
        wrapper = keys.key_wrapper_from_env({"KEYCHAIN_ALLOW_PLAINTEXT_KEYS": "1"})
        assert wrapper.seals is False

    def test_undersized_master_key_is_refused(self):
        with pytest.raises(ConfigurationError):
            keys.key_wrapper_from_env({"KEYCHAIN_MASTER_KEY": "aabb"})
