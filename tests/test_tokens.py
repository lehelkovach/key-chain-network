"""Capability token issuance and verification."""

import datetime

import pytest

from keychain import certificates, keys, tokens
from keychain.canonical import b64u_decode, b64u_encode, canonical_json, utcnow
from keychain.errors import TrustError, ValidationError

from tests.test_certificates import make_agent, make_root


@pytest.fixture
def chain_fixture():
    """A worker under an orchestrator under a root, with the worker's key."""
    root_key, root_certificate = make_root()
    orchestrator_key, orchestrator = make_agent(
        root_key,
        root_certificate,
        "agent:cursor.iac-bus.0",
        role="orchestrator",
        capabilities=("agent.mint", "bus.post", "bus.read", "lock.acquire"),
    )
    worker_key, worker = make_agent(
        orchestrator_key,
        orchestrator,
        "agent:cursor.iac-bus.0-1",
        capabilities=("bus.post", "bus.read"),
        parent_agent_uuid=orchestrator["subject"]["agent_uuid"],
    )
    return {
        "root_key_id": root_certificate["subject"]["key_id"],
        "root_certificate": root_certificate,
        "root_key": root_key,
        "chain": [worker, orchestrator, root_certificate],
        "worker_key": worker_key,
        "worker": worker,
    }


def issue(chain_fixture, **overrides):
    params = {
        "signing_key": chain_fixture["worker_key"],
        "subject": chain_fixture["worker"]["subject"],
        "capabilities": ("bus.post", "bus.read"),
        "audience": "iac-bus",
        "ttl_seconds": 3600,
        "chain": chain_fixture["chain"],
        "issuer_ref": "agent:cursor.iac-bus.0-1",
        "root_key_id": chain_fixture["root_key_id"],
    }
    params.update(overrides)
    signing_key = params.pop("signing_key")
    subject = params.pop("subject")
    capabilities = params.pop("capabilities")
    return tokens.issue_token(signing_key, subject, capabilities, **params)


class TestIssuance:
    def test_token_is_a_three_part_compact_jws(self, chain_fixture):
        token = issue(chain_fixture)
        assert token.count(".") == 2
        header, payload, _signature, _signing_input = tokens.decode(token)
        assert header["alg"] == "EdDSA"
        assert header["typ"] == tokens.TOKEN_TYPE
        assert header["kid"] == chain_fixture["worker"]["subject"]["key_id"]
        assert payload["sub"] == chain_fixture["worker"]["subject"]["agent_uuid"]
        assert payload["handle"] == "agent:cursor.iac-bus.0-1"
        assert payload["aud"] == ["iac-bus"]
        assert payload["exp"] - payload["iat"] == 3600

    def test_self_contained_token_carries_the_chain(self, chain_fixture):
        header, _payload, _signature, _input = tokens.decode(issue(chain_fixture))
        assert len(header["kcc"]) == 3

    def test_authority_signed_token_omits_the_chain(self, chain_fixture):
        token = issue(
            chain_fixture,
            signing_key=chain_fixture["root_key"],
            chain=None,
            issuer_ref="root:test-root",
        )
        header, _payload, _signature, _input = tokens.decode(token)
        assert "kcc" not in header

    def test_self_contained_token_must_be_signed_by_the_leaf_key(self, chain_fixture):
        with pytest.raises(ValidationError):
            issue(chain_fixture, signing_key=chain_fixture["root_key"])

    def test_capabilities_are_normalized(self, chain_fixture):
        token = issue(chain_fixture, capabilities=["BUS.read", "bus.read", "bus.post"])
        _header, payload, _signature, _input = tokens.decode(token)
        assert payload["caps"] == ["bus.post", "bus.read"]

    def test_audience_accepts_a_list(self, chain_fixture):
        token = issue(chain_fixture, audience=["iac-bus", "borgnet"])
        _header, payload, _signature, _input = tokens.decode(token)
        assert payload["aud"] == ["borgnet", "iac-bus"]

    @pytest.mark.parametrize("ttl", [0, -1, "3600", True])
    def test_invalid_ttl_is_rejected(self, chain_fixture, ttl):
        with pytest.raises(ValidationError):
            issue(chain_fixture, ttl_seconds=ttl)

    def test_ttl_is_bounded(self, chain_fixture):
        with pytest.raises(ValidationError):
            issue(chain_fixture, ttl_seconds=tokens.MAX_TTL_SECONDS + 1)

    def test_extra_claims_cannot_shadow_reserved_ones(self, chain_fixture):
        with pytest.raises(ValidationError):
            issue(chain_fixture, extra_claims={"exp": 0})

    def test_extra_claims_are_included(self, chain_fixture):
        token = issue(chain_fixture, extra_claims={"channel": "task.demo"})
        _header, payload, _signature, _input = tokens.decode(token)
        assert payload["channel"] == "task.demo"

    def test_each_token_gets_a_distinct_jti(self, chain_fixture):
        first = tokens.decode(issue(chain_fixture))[1]
        second = tokens.decode(issue(chain_fixture))[1]
        assert first["jti"] != second["jti"]


class TestDecode:
    @pytest.mark.parametrize("bad", ["", "one.two", "a.b.c.d", 42])
    def test_malformed_tokens_are_rejected(self, bad):
        with pytest.raises(ValidationError):
            tokens.decode(bad)

    def test_non_json_segments_are_rejected(self):
        with pytest.raises(ValidationError):
            tokens.decode("%s.%s.sig" % (b64u_encode(b"nope"), b64u_encode(b"nope")))

    def test_non_object_segments_are_rejected(self):
        segment = b64u_encode(canonical_json([1, 2]))
        with pytest.raises(ValidationError):
            tokens.decode("%s.%s.sig" % (segment, segment))


class TestVerification:
    def test_a_valid_self_contained_token_verifies_offline(self, chain_fixture):
        result = tokens.verify_token(
            issue(chain_fixture),
            trusted_root_key_ids=[chain_fixture["root_key_id"]],
            audience="iac-bus",
        )
        assert result.valid, result.errors
        assert result.capabilities == ["bus.post", "bus.read"]
        assert result.chain_verification.chain_length == 3

    def test_an_untrusted_root_fails(self, chain_fixture):
        result = tokens.verify_token(
            issue(chain_fixture), trusted_root_key_ids=["someone-else"]
        )
        assert not result.valid
        assert any("not trusted" in error for error in result.errors)

    def test_a_tampered_payload_fails(self, chain_fixture):
        header, payload, signature, _input = tokens.decode(issue(chain_fixture))
        payload["caps"] = ["*"]
        forged = "%s.%s.%s" % (
            b64u_encode(canonical_json(header)),
            b64u_encode(canonical_json(payload)),
            signature,
        )
        result = tokens.verify_token(
            forged, trusted_root_key_ids=[chain_fixture["root_key_id"]]
        )
        assert not result.valid
        assert any("signature is invalid" in error for error in result.errors)

    def test_capabilities_beyond_the_certificate_are_rejected(self, chain_fixture):
        # Signed correctly by the worker, but claiming more than its certificate.
        token = issue(chain_fixture, capabilities=["agent.mint"])
        result = tokens.verify_token(
            token, trusted_root_key_ids=[chain_fixture["root_key_id"]]
        )
        assert not result.valid
        assert any("beyond its leaf certificate" in error for error in result.errors)

    def test_an_expired_token_fails(self, chain_fixture):
        token = issue(
            chain_fixture, ttl_seconds=60, now=utcnow() - datetime.timedelta(hours=2)
        )
        result = tokens.verify_token(
            token, trusted_root_key_ids=[chain_fixture["root_key_id"]]
        )
        assert not result.valid
        assert any("expired" in error for error in result.errors)

    def test_a_future_dated_token_fails(self, chain_fixture):
        token = issue(chain_fixture, now=utcnow() + datetime.timedelta(hours=2))
        result = tokens.verify_token(
            token, trusted_root_key_ids=[chain_fixture["root_key_id"]]
        )
        assert not result.valid
        assert any("not yet valid" in error for error in result.errors)

    def test_small_clock_skew_is_tolerated(self, chain_fixture):
        token = issue(
            chain_fixture,
            ttl_seconds=60,
            now=utcnow() - datetime.timedelta(seconds=90),
        )
        result = tokens.verify_token(
            token, trusted_root_key_ids=[chain_fixture["root_key_id"]]
        )
        assert result.valid, result.errors

    def test_audience_mismatch_fails(self, chain_fixture):
        result = tokens.verify_token(
            issue(chain_fixture, audience="borgnet"),
            trusted_root_key_ids=[chain_fixture["root_key_id"]],
            audience="iac-bus",
        )
        assert not result.valid
        assert any("audience" in error for error in result.errors)

    def test_a_missing_audience_fails_when_one_is_required(self, chain_fixture):
        result = tokens.verify_token(
            issue(chain_fixture, audience=None),
            trusted_root_key_ids=[chain_fixture["root_key_id"]],
            audience="iac-bus",
        )
        assert not result.valid

    def test_audience_is_not_checked_when_not_requested(self, chain_fixture):
        result = tokens.verify_token(
            issue(chain_fixture, audience="borgnet"),
            trusted_root_key_ids=[chain_fixture["root_key_id"]],
        )
        assert result.valid, result.errors

    def test_required_capabilities_are_enforced(self, chain_fixture):
        result = tokens.verify_token(
            issue(chain_fixture),
            trusted_root_key_ids=[chain_fixture["root_key_id"]],
            required_capabilities=["agent.mint"],
        )
        assert not result.valid
        assert any("missing required capabilities" in error for error in result.errors)

    def test_required_capabilities_that_are_held_pass(self, chain_fixture):
        result = tokens.verify_token(
            issue(chain_fixture),
            trusted_root_key_ids=[chain_fixture["root_key_id"]],
            required_capabilities=["bus.post"],
        )
        assert result.valid, result.errors

    def test_authority_signed_token_needs_a_resolver(self, chain_fixture):
        token = issue(chain_fixture, signing_key=chain_fixture["root_key"], chain=None)
        result = tokens.verify_token(token, trusted_root_key_ids=[chain_fixture["root_key_id"]])
        assert not result.valid
        assert any("no key resolver" in error for error in result.errors)

    def test_authority_signed_token_verifies_through_a_resolver(self, chain_fixture):
        token = issue(chain_fixture, signing_key=chain_fixture["root_key"], chain=None)
        jwk = chain_fixture["root_certificate"]["subject"]["public_key"]
        result = tokens.verify_token(token, resolve_jwk=lambda kid: jwk)
        assert result.valid, result.errors

    def test_an_unknown_signing_key_fails(self, chain_fixture):
        token = issue(chain_fixture, signing_key=chain_fixture["root_key"], chain=None)
        result = tokens.verify_token(token, resolve_jwk=lambda kid: None)
        assert not result.valid
        assert any("unknown token signing key" in error for error in result.errors)

    def test_subject_must_match_the_leaf_certificate(self, chain_fixture):
        other_subject = dict(
            chain_fixture["worker"]["subject"], agent_uuid="00000000-0000-4000-8000-000000000000"
        )
        token = issue(chain_fixture, subject=other_subject)
        result = tokens.verify_token(
            token, trusted_root_key_ids=[chain_fixture["root_key_id"]]
        )
        assert not result.valid
        assert any("does not match the leaf certificate" in error for error in result.errors)

    def test_revocation_callback_is_honoured(self, chain_fixture):
        result = tokens.verify_token(
            issue(chain_fixture),
            trusted_root_key_ids=[chain_fixture["root_key_id"]],
            is_revoked=lambda cert: cert["cert_type"] == certificates.CERT_TYPE_AGENT,
        )
        assert not result.valid
        assert any("revoked" in error for error in result.errors)

    def test_a_garbage_token_fails_cleanly(self):
        result = tokens.verify_token("not-a-token", trusted_root_key_ids=["r"])
        assert not result.valid
        assert result.payload is None

    def test_raise_for_status(self, chain_fixture):
        with pytest.raises(TrustError):
            tokens.verify_token("nope", trusted_root_key_ids=["r"]).raise_for_status()
        good = tokens.verify_token(
            issue(chain_fixture), trusted_root_key_ids=[chain_fixture["root_key_id"]]
        )
        assert good.raise_for_status() is good

    def test_to_dict_includes_the_chain_result(self, chain_fixture):
        payload = tokens.verify_token(
            issue(chain_fixture), trusted_root_key_ids=[chain_fixture["root_key_id"]]
        ).to_dict()
        assert payload["valid"] is True
        assert payload["chain"]["chain_length"] == 3
        assert payload["claims"]["handle"] == "agent:cursor.iac-bus.0-1"


class TestInteroperability:
    def test_segments_are_standard_unpadded_base64url_json(self, chain_fixture):
        import json

        header_segment = issue(chain_fixture).split(".")[0]
        assert "=" not in header_segment
        assert json.loads(b64u_decode(header_segment).decode("utf-8"))["alg"] == "EdDSA"

    def test_signature_covers_the_ascii_signing_input(self, chain_fixture):
        token = issue(chain_fixture)
        header, _payload, signature, signing_input = tokens.decode(token)
        assert signing_input == token.rsplit(".", 1)[0].encode("ascii")
        public_key = keys.load_public_jwk(header["kcc"][0]["subject"]["public_key"])
        assert keys.verify(public_key, signature, signing_input)
