"""The published JSON schemas must describe what KeyChain actually emits.

These tests exist because a schema that drifts from the implementation is worse
than no schema: clients written against it will reject valid documents. Each test
validates real service output, not a hand-written example.
"""

import json
import os

import pytest

jsonschema = pytest.importorskip("jsonschema")

from keychain import tokens  # noqa: E402
from keychain.store import CUSTODY_KEYCHAIN  # noqa: E402

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schemas")


def load_schema(name):
    with open(os.path.join(SCHEMA_DIR, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


def validator_for(name):
    schema = load_schema(name)
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


@pytest.fixture
def identity_document(client, auth_headers):
    return client.post(
        "/agents/mint",
        json={"brand": "cursor", "repo_locale": "iac-bus", "role": "orchestrator",
              "medium": "web", "session_id": "s-1"},
        headers=auth_headers,
    ).json


class TestSchemasAreWellFormed:
    @pytest.mark.parametrize(
        "name",
        [
            "agent-identity.schema.json",
            "capability-token.schema.json",
            "identity-certificate.schema.json",
            "mint-request.schema.json",
        ],
    )
    def test_schema_compiles(self, name):
        assert validator_for(name) is not None


class TestIdentityCertificate:
    def test_a_minted_agent_certificate_validates(self, identity_document):
        validator_for("identity-certificate.schema.json").validate(
            identity_document["certificate"]
        )

    def test_every_certificate_in_the_chain_validates(self, identity_document):
        validator = validator_for("identity-certificate.schema.json")
        for certificate in identity_document["certificate_chain"]:
            validator.validate(certificate)

    def test_the_root_certificate_validates(self, client):
        root = client.get("/.well-known/keychain/roots.json").json["roots"][0]
        validator_for("identity-certificate.schema.json").validate(root["certificate"])

    def test_a_delegated_child_certificate_validates(self, client, auth_headers):
        parent = client.post(
            "/agents/mint",
            json={"brand": "cursor", "repo_locale": "iac-bus", "role": "orchestrator",
                  "custody": CUSTODY_KEYCHAIN},
            headers=auth_headers,
        ).json
        child = client.post(
            "/agents/mint",
            json={"brand": "cursor", "repo_locale": "iac-bus", "role": "worker",
                  "parent_agent_uuid": parent["agent_uuid"]},
            headers=auth_headers,
        ).json
        validator = validator_for("identity-certificate.schema.json")
        for certificate in child["certificate_chain"]:
            validator.validate(certificate)

    def test_the_schema_rejects_an_unknown_version(self, identity_document):
        certificate = dict(identity_document["certificate"], kc_version="kc2")
        with pytest.raises(jsonschema.ValidationError):
            validator_for("identity-certificate.schema.json").validate(certificate)

    def test_the_schema_rejects_extra_members(self, identity_document):
        # Extra members would also break the signature; the schema says so too.
        certificate = dict(identity_document["certificate"], surprise=1)
        with pytest.raises(jsonschema.ValidationError):
            validator_for("identity-certificate.schema.json").validate(certificate)


class TestAgentIdentityDocument:
    def test_a_mint_response_validates(self, identity_document):
        validator_for("agent-identity.schema.json").validate(identity_document)

    def test_an_idempotent_mint_response_validates(self, client, auth_headers,
                                                   identity_document):
        again = client.post(
            "/agents/mint",
            json={"brand": "cursor", "repo_locale": "iac-bus", "role": "orchestrator",
                  "medium": "web", "session_id": "s-1"},
            headers=auth_headers,
        ).json
        assert again["created"] is False
        validator_for("agent-identity.schema.json").validate(again)

    def test_a_keychain_custody_response_validates(self, client, auth_headers):
        document = client.post(
            "/agents/mint",
            json={"brand": "cursor", "repo_locale": "repo-x", "role": "worker",
                  "custody": CUSTODY_KEYCHAIN},
            headers=auth_headers,
        ).json
        validator_for("agent-identity.schema.json").validate(document)
        assert "private_key" not in document


class TestMintRequest:
    @pytest.mark.parametrize(
        "payload",
        [
            {"brand": "cursor", "repo_locale": "iac-bus"},
            {"brand": "cursor", "repo_locale": "iac-bus", "ordinal_path": "0-4-8",
             "parent_agent_uuid": "b8f2", "role": "worker", "medium": "web",
             "session_id": "s-1"},
            {"logical_handle": "agent:cursor.iac-bus.0"},
            {"brand": "cursor", "repo_locale": "iac-bus", "custody": "keychain",
             "issuer": "parent", "capabilities": ["bus.read"], "ttl_seconds": 60,
             "metadata": {"branch": "cursor/demo"}},
        ],
    )
    def test_valid_requests_validate(self, payload):
        validator_for("mint-request.schema.json").validate(payload)

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"brand": "cursor"},
            {"brand": "cursor", "repo_locale": "iac-bus", "ordinal_path": "0-"},
            {"brand": "cursor", "repo_locale": "iac-bus", "medium": "telepathy"},
            {"brand": "cursor", "repo_locale": "iac-bus", "custody": "vault"},
            {"brand": "cursor", "repo_locale": "iac-bus", "ttl_seconds": 0},
            {"brand": "cursor", "repo_locale": "iac-bus", "unexpected": "field"},
        ],
    )
    def test_invalid_requests_are_rejected(self, payload):
        with pytest.raises(jsonschema.ValidationError):
            validator_for("mint-request.schema.json").validate(payload)

    def test_the_acp_v2_register_example_validates(self):
        # Verbatim from iac-bus/docs/ACP_PROTOCOL_V2.md section 4.1.
        validator_for("mint-request.schema.json").validate(
            {
                "brand": "cursor",
                "repo_locale": "repo-x",
                "ordinal_path": "0-1",
                "parent_agent_uuid": "optional-uuid",
                "role": "worker",
                "medium": "web",
                "session_id": "optional-session",
            }
        )


class TestCapabilityToken:
    def test_a_self_contained_token_validates(self, client, auth_headers):
        minted = client.post(
            "/agents/mint",
            json={"brand": "cursor", "repo_locale": "iac-bus", "role": "orchestrator",
                  "custody": CUSTODY_KEYCHAIN},
            headers=auth_headers,
        ).json
        issued = client.post(
            "/tokens/issue",
            json={"agent_uuid": minted["agent_uuid"], "audience": "iac-bus"},
            headers=auth_headers,
        ).json
        header, payload, _signature, _input = tokens.decode(issued["token"])
        validator_for("capability-token.schema.json").validate(
            {"header": header, "payload": payload}
        )
        assert "kcc" in header

    def test_an_authority_signed_token_validates(self, client, auth_headers):
        minted = client.post(
            "/agents/mint",
            json={"brand": "cursor", "repo_locale": "iac-bus", "role": "worker"},
            headers=auth_headers,
        ).json
        issued = client.post(
            "/tokens/issue",
            json={"agent_uuid": minted["agent_uuid"]},
            headers=auth_headers,
        ).json
        header, payload, _signature, _input = tokens.decode(issued["token"])
        validator_for("capability-token.schema.json").validate(
            {"header": header, "payload": payload}
        )
        assert "kcc" not in header

    def test_the_schema_rejects_a_different_algorithm(self):
        with pytest.raises(jsonschema.ValidationError):
            validator_for("capability-token.schema.json").validate(
                {
                    "header": {"alg": "HS256", "typ": "kc1-token", "kid": "a" * 43},
                    "payload": {
                        "kc_version": "kc1",
                        "jti": "0f1d8e1a-0000-4000-8000-000000000000",
                        "iss": "root:test",
                        "sub": "0f1d8e1a-0000-4000-8000-000000000000",
                        "handle": "agent:cursor.iac-bus.0",
                        "caps": [],
                        "iat": 0,
                        "nbf": 0,
                        "exp": 1,
                    },
                }
            )
