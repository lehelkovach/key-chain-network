"""HTTP surface: auth, error mapping, and the minting endpoints."""

import pytest

from keychain import keys


def mint(client, auth_headers, **overrides):
    payload = {"brand": "cursor", "repo_locale": "iac-bus", "role": "worker",
               "medium": "api"}
    payload.update(overrides)
    return client.post("/agents/mint", json=payload, headers=auth_headers)


class TestAuth:
    def test_health_is_open(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json["status"] == "ok"

    def test_discovery_endpoints_are_open(self, client):
        assert client.get("/.well-known/keychain/jwks.json").status_code == 200
        assert client.get("/.well-known/keychain/roots.json").status_code == 200

    def test_minting_requires_a_token(self, client):
        response = client.post("/agents/mint", json={})
        assert response.status_code == 401
        assert response.json["code"] == "unauthorized"

    def test_a_wrong_token_is_rejected(self, client):
        response = client.post(
            "/agents/mint", json={}, headers={"Authorization": "Bearer nope"}
        )
        assert response.status_code == 401

    def test_a_malformed_authorization_header_is_rejected(self, client):
        response = client.post(
            "/agents/mint", json={}, headers={"Authorization": "test-token"}
        )
        assert response.status_code == 401

    def test_auth_is_optional_when_no_token_is_configured(self, service):
        from server import create_app

        service.config.api_token = ""
        app = create_app(service=service, config=service.config)
        app.testing = True
        with app.test_client() as open_client:
            assert open_client.get("/metrics").status_code == 200


class TestHealthAndMetrics:
    def test_health_reports_custody_and_counts(self, client, auth_headers):
        mint(client, auth_headers)
        payload = client.get("/health").json
        assert payload["service"] == "key-chain-network"
        assert payload["key_custody_sealed"] is True
        assert payload["auth_required"] is True
        assert payload["agents"] == 1

    def test_metrics_never_leaks_the_api_token(self, client, auth_headers):
        payload = client.get("/metrics", headers=auth_headers).json
        assert "api_token" not in payload["config"]
        assert payload["config"]["auth_required"] is True

    def test_jwks_publishes_only_public_keys(self, client):
        payload = client.get("/.well-known/keychain/jwks.json").json
        assert payload["keys"]
        assert all("d" not in key for key in payload["keys"])

    def test_public_roots_include_the_root_certificate(self, client):
        roots = client.get("/.well-known/keychain/roots.json").json["roots"]
        assert roots[0]["certificate"]["cert_type"] == "root"
        assert "sealed_private_key" not in roots[0]


class TestErrorMapping:
    def test_a_missing_body_is_a_400(self, client, auth_headers):
        response = client.post("/agents/mint", headers=auth_headers)
        assert response.status_code == 400
        assert response.json["code"] == "invalid_request"

    def test_a_non_object_body_is_a_400(self, client, auth_headers):
        response = client.post("/agents/mint", json=[1, 2], headers=auth_headers)
        assert response.status_code == 400

    def test_validation_details_are_returned(self, client, auth_headers):
        response = client.post(
            "/agents/mint", json={"role": "worker"}, headers=auth_headers
        )
        assert response.status_code == 400
        assert "brand is required" in response.json["details"]

    def test_an_unknown_agent_is_a_404(self, client, auth_headers):
        response = client.get("/agents/agent:cursor.iac-bus.9", headers=auth_headers)
        assert response.status_code == 404
        assert response.json["code"] == "not_found"

    def test_an_unknown_route_returns_json(self, client, auth_headers):
        response = client.get("/nope", headers=auth_headers)
        assert response.status_code == 404
        assert response.json["code"] == "not_found"

    def test_a_wrong_method_returns_json(self, client):
        response = client.put("/health")
        assert response.status_code == 405
        assert response.json["code"] == "method_not_allowed"

    def test_a_reserved_path_segment_reads_as_a_missing_agent(self, client,
                                                              auth_headers):
        # GET /agents/mint falls through to the agent lookup route.
        response = client.get("/agents/mint", headers=auth_headers)
        assert response.status_code == 404


class TestMintEndpoint:
    def test_a_new_identity_returns_201(self, client, auth_headers):
        response = mint(client, auth_headers)
        assert response.status_code == 201
        payload = response.json
        assert payload["created"] is True
        assert payload["logical_handle"] == "agent:cursor.iac-bus.0"
        assert payload["endpoint_handle"] == "agent:cursor.iac-bus.0@api"
        assert payload["certificate_chain"]
        assert payload["private_key"]["d"]
        assert "does not retain it" in payload["private_key_notice"]

    def test_a_repeat_mint_returns_200_without_the_private_key(self, client,
                                                              auth_headers):
        mint(client, auth_headers)
        response = mint(client, auth_headers)
        assert response.status_code == 200
        assert response.json["created"] is False
        assert "private_key" not in response.json

    def test_a_conflict_returns_409_with_a_conflict_code(self, client, auth_headers):
        mint(client, auth_headers)
        response = mint(client, auth_headers, role="reviewer")
        assert response.status_code == 409
        assert response.json["conflict_code"] == "HANDLE_ROLE_MISMATCH"

    def test_a_missing_parent_returns_404(self, client, auth_headers):
        response = mint(
            client, auth_headers, ordinal_path="0-1",
            parent_agent_uuid="00000000-0000-4000-8000-000000000000",
        )
        assert response.status_code == 404

    def test_a_child_is_minted_under_its_parent(self, client, auth_headers):
        parent = mint(client, auth_headers, role="orchestrator",
                      custody="keychain").json
        child = mint(client, auth_headers,
                     parent_agent_uuid=parent["agent_uuid"]).json
        assert child["logical_handle"] == "agent:cursor.iac-bus.0-0"
        assert len(child["certificate_chain"]) == 3

    def test_a_caller_supplied_key_keeps_the_private_half_out_of_the_response(
        self, client, auth_headers
    ):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        response = mint(client, auth_headers, public_key=jwk)
        assert response.status_code == 201
        assert "private_key" not in response.json
        assert response.json["key_id"] == jwk["kid"]


class TestAgentEndpoints:
    def test_listing_and_filtering(self, client, auth_headers):
        mint(client, auth_headers, role="orchestrator")
        mint(client, auth_headers, repo_locale="repo-x")
        assert client.get("/agents", headers=auth_headers).json["count"] == 2
        filtered = client.get("/agents?repo_locale=repo-x", headers=auth_headers)
        assert filtered.json["count"] == 1

    def test_pagination_is_bounded(self, client, auth_headers):
        mint(client, auth_headers)
        response = client.get("/agents?limit=9999", headers=auth_headers)
        assert response.status_code == 200

    def test_get_by_handle_and_uuid(self, client, auth_headers):
        minted = mint(client, auth_headers).json
        by_handle = client.get(
            "/agents/agent:cursor.iac-bus.0", headers=auth_headers
        ).json
        by_uuid = client.get(
            "/agents/%s" % minted["agent_uuid"], headers=auth_headers
        ).json
        assert by_handle["agent_uuid"] == by_uuid["agent_uuid"]
        assert by_handle["certificate_chain"]

    def test_chain_can_be_suppressed(self, client, auth_headers):
        mint(client, auth_headers)
        response = client.get(
            "/agents/agent:cursor.iac-bus.0?chain=0", headers=auth_headers
        )
        assert "certificate_chain" not in response.json

    def test_the_chain_endpoint_is_distinct_from_the_agent_endpoint(self, client,
                                                                   auth_headers):
        mint(client, auth_headers)
        response = client.get(
            "/agents/agent:cursor.iac-bus.0/chain", headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json["certificate_chain"][0]["cert_type"] == "agent"

    def test_heartbeat(self, client, auth_headers):
        minted = mint(client, auth_headers, medium="web").json
        response = client.post(
            "/agents/heartbeat",
            json={"agent_uuid": minted["agent_uuid"], "medium": "web"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json["success"] is True
        assert response.json["last_seen_at"]

    def test_revocation_cascades_and_is_listed(self, client, auth_headers):
        parent = mint(client, auth_headers, role="orchestrator",
                      custody="keychain").json
        mint(client, auth_headers, parent_agent_uuid=parent["agent_uuid"])
        response = client.post(
            "/agents/%s/revoke" % parent["agent_uuid"],
            json={"reason": "compromised"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert len(response.json["revoked"]) == 2
        listed = client.get("/revocations", headers=auth_headers).json["revocations"]
        assert {entry["reason"] for entry in listed} == {"compromised"}

    def test_revocation_without_a_body_still_works(self, client, auth_headers):
        minted = mint(client, auth_headers).json
        response = client.post(
            "/agents/%s/revoke" % minted["agent_uuid"], headers=auth_headers
        )
        assert response.status_code == 200

    def test_the_audit_log_records_mints(self, client, auth_headers):
        mint(client, auth_headers)
        entries = client.get("/audit", headers=auth_headers).json["audit"]
        assert any(entry["event"] == "agent.mint" for entry in entries)


class TestTrustRootEndpoints:
    def test_creating_a_root(self, client, auth_headers):
        response = client.post(
            "/trust/roots", json={"name": "second-root"}, headers=auth_headers
        )
        assert response.status_code == 201
        assert response.json["certificate"]["cert_type"] == "root"

    def test_a_duplicate_root_is_a_409(self, client, auth_headers):
        client.post("/trust/roots", json={"name": "dup"}, headers=auth_headers)
        response = client.post(
            "/trust/roots", json={"name": "dup"}, headers=auth_headers
        )
        assert response.status_code == 409

    def test_listing_roots_hides_private_material(self, client, auth_headers):
        client.post("/trust/roots", json={"name": "another"}, headers=auth_headers)
        roots = client.get("/trust/roots", headers=auth_headers).json["roots"]
        assert all("sealed_private_key" not in root for root in roots)
        assert all(root["has_private_key"] for root in roots)

    def test_the_default_root_can_be_moved(self, client, auth_headers):
        created = client.post(
            "/trust/roots", json={"name": "promote-me"}, headers=auth_headers
        ).json
        response = client.post(
            "/trust/roots/%s/default" % created["root_id"], headers=auth_headers
        )
        assert response.status_code == 200
        assert client.get("/health").json["default_root_key_id"] == created["key_id"]


class TestVerificationEndpoints:
    def test_a_chain_verifies(self, client, auth_headers):
        minted = mint(client, auth_headers).json
        response = client.post(
            "/verify/certificate",
            json={"certificate_chain": minted["certificate_chain"]},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json["valid"] is True

    def test_a_single_certificate_verifies(self, client, auth_headers):
        minted = mint(client, auth_headers).json
        response = client.post(
            "/verify/certificate",
            json={"certificate": minted["certificate"]},
            headers=auth_headers,
        )
        assert response.json["valid"] is True

    def test_a_tampered_chain_reports_errors(self, client, auth_headers):
        minted = mint(client, auth_headers).json
        chain = minted["certificate_chain"]
        chain[0]["capabilities"] = ["*"]
        response = client.post(
            "/verify/certificate", json={"certificate_chain": chain},
            headers=auth_headers,
        )
        assert response.json["valid"] is False
        assert response.json["errors"]

    def test_verification_needs_something_to_verify(self, client, auth_headers):
        response = client.post("/verify/certificate", json={}, headers=auth_headers)
        assert response.status_code == 400


class TestTokenEndpoints:
    def test_issue_then_verify(self, client, auth_headers):
        minted = mint(client, auth_headers, role="orchestrator",
                      custody="keychain").json
        issued = client.post(
            "/tokens/issue",
            json={"agent_uuid": minted["agent_uuid"], "audience": "iac-bus"},
            headers=auth_headers,
        )
        assert issued.status_code == 200
        assert issued.json["token_type"] == "Bearer"
        verified = client.post(
            "/tokens/verify",
            json={"token": issued.json["token"], "audience": "iac-bus"},
            headers=auth_headers,
        )
        assert verified.status_code == 200
        assert verified.json["valid"] is True

    def test_issue_accepts_a_logical_handle(self, client, auth_headers):
        mint(client, auth_headers, role="orchestrator", custody="keychain")
        issued = client.post(
            "/tokens/issue",
            json={"logical_handle": "agent:cursor.iac-bus.0"},
            headers=auth_headers,
        )
        assert issued.status_code == 200

    def test_issue_requires_an_agent_reference(self, client, auth_headers):
        response = client.post("/tokens/issue", json={}, headers=auth_headers)
        assert response.status_code == 400

    def test_an_invalid_token_returns_403(self, client, auth_headers):
        response = client.post(
            "/tokens/verify", json={"token": "not-a-token"}, headers=auth_headers
        )
        assert response.status_code == 403
        assert response.json["valid"] is False

    def test_verify_requires_a_token(self, client, auth_headers):
        response = client.post("/tokens/verify", json={}, headers=auth_headers)
        assert response.status_code == 400

    def test_required_capabilities_are_enforced_over_http(self, client, auth_headers):
        minted = mint(client, auth_headers, role="worker", custody="keychain").json
        issued = client.post(
            "/tokens/issue", json={"agent_uuid": minted["agent_uuid"]},
            headers=auth_headers,
        ).json
        response = client.post(
            "/tokens/verify",
            json={"token": issued["token"], "required_capabilities": ["agent.mint"]},
            headers=auth_headers,
        )
        assert response.status_code == 403
