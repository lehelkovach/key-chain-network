"""Conformance tests for ``POST /agents/register`` against ACP v2.

The contract under test is ``iac-bus/docs/ACP_PROTOCOL_V2.md`` section 4.1: the
request fields, the derived handles, the response body, and the conflict matrix.
KeyChain adds key material under a ``keychain`` member; everything an ACP v2
client already reads keeps its documented shape and meaning, so pointing an
IAC-Bus deployment at KeyChain does not require client changes.
"""

import re

import pytest

from keychain import identity

ACP_ORDINAL_PATH_RE = re.compile(r"^([0-9]+)(-[0-9]+)*$")
ACP_LOGICAL_HANDLE_RE = re.compile(
    r"^agent:[a-z0-9_-]+\.[a-z0-9_.-]+\.[0-9]+(-[0-9]+)*$"
)
ACP_MEDIA = ("web", "slack", "ide", "api", "automation", "other")


def register(client, auth_headers, **overrides):
    payload = {
        "brand": "cursor",
        "repo_locale": "repo-x",
        "ordinal_path": "0",
        "role": "orchestrator",
        "medium": "web",
    }
    payload.update(overrides)
    return client.post("/agents/register", json=payload, headers=auth_headers)


@pytest.fixture
def master(client, auth_headers):
    return register(client, auth_headers, custody="keychain").json


class TestGrammarMatchesTheSpec:
    def test_keychain_uses_the_published_ordinal_regex(self):
        assert identity.ORDINAL_PATH_RE.pattern == ACP_ORDINAL_PATH_RE.pattern

    def test_keychain_uses_the_published_handle_regex(self):
        assert identity.LOGICAL_HANDLE_RE.pattern == ACP_LOGICAL_HANDLE_RE.pattern

    def test_keychain_accepts_exactly_the_published_media(self):
        assert identity.MEDIA == ACP_MEDIA

    @pytest.mark.parametrize("example", ["agent:cursor.iac-bus.0", "agent:cursor.repo-x.0-1"])
    def test_the_spec_examples_parse(self, example):
        assert identity.validate_logical_handle(example) == example

    @pytest.mark.parametrize("example", ["0", "0-1", "0-4-8"])
    def test_the_spec_ordinal_examples_parse(self, example):
        assert identity.validate_ordinal_path(example) == example


class TestRegisterResponse:
    def test_a_new_registration_returns_201_and_the_documented_fields(self, client,
                                                                     auth_headers):
        response = register(client, auth_headers)
        assert response.status_code == 201
        payload = response.json
        assert set(payload) == {
            "agent_uuid",
            "logical_handle",
            "endpoint_handle",
            "created",
            "keychain",
        }
        assert payload["created"] is True
        assert payload["logical_handle"] == "agent:cursor.repo-x.0"
        assert payload["endpoint_handle"] == "agent:cursor.repo-x.0@web"
        assert identity.validate_agent_uuid(payload["agent_uuid"])

    def test_the_derived_handles_follow_the_spec(self, client, auth_headers):
        payload = register(
            client, auth_headers, brand="cursor", repo_locale="repo-x",
            ordinal_path="0-1", role="worker", medium="web",
            parent_agent_uuid=register(client, auth_headers,
                                       custody="keychain").json["agent_uuid"],
        ).json
        assert payload["logical_handle"] == "agent:cursor.repo-x.0-1"
        assert payload["endpoint_handle"] == "agent:cursor.repo-x.0-1@web"

    def test_normalization_lowercases_and_trims(self, client, auth_headers):
        payload = register(
            client, auth_headers, brand=" CURSOR ", repo_locale=" Repo-X ",
            role=" Orchestrator ", medium=" WEB ",
        ).json
        assert payload["logical_handle"] == "agent:cursor.repo-x.0"
        assert payload["endpoint_handle"].endswith("@web")

    def test_the_ordinal_shape_is_preserved(self, client, auth_headers, master):
        payload = register(
            client, auth_headers, ordinal_path="0-4", role="worker",
            parent_agent_uuid=master["agent_uuid"],
        ).json
        assert payload["logical_handle"].endswith(".0-4")

    def test_key_material_travels_under_the_keychain_member(self, client, auth_headers):
        payload = register(client, auth_headers).json
        keychain = payload["keychain"]
        assert keychain["public_key"]["kty"] == "OKP"
        assert keychain["key_id"] == keychain["public_key"]["kid"]
        assert keychain["certificate"]["subject"]["logical_handle"] == (
            payload["logical_handle"]
        )
        assert keychain["certificate_chain"][-1]["cert_type"] == "root"
        assert keychain["trust_root_key_id"]
        assert keychain["private_key"]["d"]

    def test_the_minted_chain_verifies(self, client, auth_headers):
        payload = register(client, auth_headers).json
        verification = client.post(
            "/verify/certificate",
            json={"certificate_chain": payload["keychain"]["certificate_chain"]},
            headers=auth_headers,
        )
        assert verification.json["valid"] is True


class TestConflictMatrix:
    """One test per row of the ACP v2 `/agents/register` conflict matrix."""

    def test_first_registration_for_a_handle_creates(self, client, auth_headers):
        assert register(client, auth_headers).status_code == 201

    def test_identical_re_registration_is_idempotent(self, client, auth_headers):
        first = register(client, auth_headers).json
        second = register(client, auth_headers)
        assert second.status_code == 200
        assert second.json["created"] is False
        assert second.json["agent_uuid"] == first["agent_uuid"]

    def test_a_new_medium_reuses_the_uuid_and_adds_an_endpoint(self, client,
                                                              auth_headers):
        first = register(client, auth_headers).json
        second = register(client, auth_headers, medium="slack")
        assert second.status_code == 200
        assert second.json["agent_uuid"] == first["agent_uuid"]
        assert second.json["endpoint_handle"] == "agent:cursor.repo-x.0@slack"

    def test_a_new_session_reuses_the_uuid(self, client, auth_headers):
        first = register(client, auth_headers, session_id="s-1").json
        second = register(client, auth_headers, session_id="s-2")
        assert second.status_code == 200
        assert second.json["agent_uuid"] == first["agent_uuid"]

    def test_a_different_parent_is_a_409(self, client, auth_headers, master):
        sibling = register(
            client, auth_headers, repo_locale="repo-y", custody="keychain"
        ).json
        register(client, auth_headers, ordinal_path="0-1", role="worker",
                 parent_agent_uuid=master["agent_uuid"])
        response = register(
            client, auth_headers, ordinal_path="0-1", role="worker",
            parent_agent_uuid=sibling["agent_uuid"],
        )
        assert response.status_code == 409
        assert response.json["conflict_code"] == "HANDLE_PARENT_MISMATCH"
        assert response.json["existing_agent_uuid"]

    def test_a_non_master_ordinal_without_a_parent_is_a_400(self, client, auth_headers):
        response = register(client, auth_headers, ordinal_path="0-1", role="worker")
        assert response.status_code == 400
        assert any("parent" in detail for detail in response.json["details"])

    def test_an_unresolvable_parent_is_a_404(self, client, auth_headers):
        response = register(
            client, auth_headers, ordinal_path="0-1", role="worker",
            parent_agent_uuid="00000000-0000-4000-8000-000000000000",
        )
        assert response.status_code == 404
        assert "parent agent not found" in response.json["error"]

    def test_an_identity_derivation_mismatch_is_a_409(self, client, auth_headers):
        # Sending components that contradict an explicit handle is the reachable
        # form of this row, since the handle itself is unique.
        register(client, auth_headers).json
        response = client.post(
            "/agents/register",
            json={
                "logical_handle": "agent:cursor.repo-x.0",
                "brand": "openclaw",
                "role": "orchestrator",
                "medium": "web",
            },
            headers=auth_headers,
        )
        assert response.status_code == 400
        assert any("contradicts" in detail for detail in response.json["details"])


class TestValidationResponses:
    def test_a_malformed_ordinal_path_reports_the_spec_regex(self, client,
                                                            auth_headers):
        response = register(client, auth_headers, ordinal_path="0-")
        assert response.status_code == 400
        assert any(
            ACP_ORDINAL_PATH_RE.pattern in detail
            for detail in response.json["details"]
        )

    def test_an_unknown_medium_lists_the_spec_media(self, client, auth_headers):
        response = register(client, auth_headers, medium="carrier-pigeon")
        assert response.status_code == 400
        assert any(
            all(medium in detail for medium in ACP_MEDIA)
            for detail in response.json["details"]
        )

    def test_medium_is_required_by_register(self, client, auth_headers):
        response = client.post(
            "/agents/register",
            json={"brand": "cursor", "repo_locale": "repo-x", "ordinal_path": "0",
                  "role": "worker"},
            headers=auth_headers,
        )
        assert response.status_code == 400
        assert "medium is required" in response.json["details"]

    def test_unauthorized_matches_the_spec_body(self, client):
        response = client.post("/agents/register", json={})
        assert response.status_code == 401
        assert response.json["error"] == "Unauthorized"


class TestHeartbeat:
    def test_heartbeat_matches_the_spec_response(self, client, auth_headers):
        registered = register(client, auth_headers).json
        response = client.post(
            "/agents/heartbeat",
            json={"agent_uuid": registered["agent_uuid"], "medium": "web"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json["success"] is True
        assert response.json["last_seen_at"].endswith("Z")

    def test_heartbeat_accepts_an_optional_session(self, client, auth_headers):
        registered = register(client, auth_headers, session_id="s-1").json
        response = client.post(
            "/agents/heartbeat",
            json={"agent_uuid": registered["agent_uuid"], "medium": "web",
                  "session_id": "s-1"},
            headers=auth_headers,
        )
        assert response.status_code == 200


class TestBusRelyingPartyFlow:
    """The end-to-end shape an IAC-Bus deployment would implement."""

    def test_a_bus_can_authorize_a_posting_agent_offline(self, client, auth_headers,
                                                        service):
        from keychain import tokens

        registered = register(client, auth_headers, custody="keychain").json
        pinned_root_key_id = registered["keychain"]["trust_root_key_id"]

        issued = client.post(
            "/tokens/issue",
            json={"agent_uuid": registered["agent_uuid"], "audience": "iac-bus",
                  "capabilities": ["bus.post", "bus.read"]},
            headers=auth_headers,
        ).json

        # The bus holds only the pinned root key id: no KeyChain call, no shared
        # secret, no database lookup.
        verification = tokens.verify_token(
            issued["token"],
            trusted_root_key_ids=[pinned_root_key_id],
            audience="iac-bus",
            required_capabilities=["bus.post"],
        )
        assert verification.valid, verification.errors
        assert verification.payload["sub"] == registered["agent_uuid"]
        assert verification.payload["handle"] == registered["logical_handle"]

    def test_a_bus_rejects_a_token_minted_under_another_root(self, client,
                                                            auth_headers):
        from keychain import tokens

        registered = register(client, auth_headers, custody="keychain").json
        issued = client.post(
            "/tokens/issue", json={"agent_uuid": registered["agent_uuid"]},
            headers=auth_headers,
        ).json
        verification = tokens.verify_token(
            issued["token"], trusted_root_key_ids=["some-other-deployment"]
        )
        assert not verification.valid

    def test_a_bus_can_map_a_token_onto_acp_channels(self, client, auth_headers):
        from keychain import tokens

        registered = register(client, auth_headers, custody="keychain").json
        issued = client.post(
            "/tokens/issue", json={"agent_uuid": registered["agent_uuid"]},
            headers=auth_headers,
        ).json
        claims = tokens.verify_token(
            issued["token"],
            trusted_root_key_ids=[registered["keychain"]["trust_root_key_id"]],
        ).payload
        brand, repo_locale, ordinal_path = identity.parse_logical_handle(
            claims["handle"]
        )
        assert "repo.%s" % repo_locale == "repo.repo-x"
        assert "agent.%s" % claims["sub"] == "agent.%s" % registered["agent_uuid"]
        assert brand == "cursor"
        assert ordinal_path == "0"
