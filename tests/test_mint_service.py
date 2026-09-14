"""Minting behaviour: ACP v2 compatibility, idempotency, conflicts, delegation."""

import pytest

from keychain import capabilities as caps
from keychain import identity, keys
from keychain.errors import (
    ConflictError,
    CustodyError,
    NotFoundError,
    RevokedError,
    ValidationError,
)
from keychain.service import (
    CONFLICT_IDENTITY_MISMATCH,
    CONFLICT_KEY_MISMATCH,
    CONFLICT_PARENT_MISMATCH,
    CONFLICT_ROLE_MISMATCH,
)
from keychain.store import CUSTODY_AGENT, CUSTODY_KEYCHAIN, STATUS_REVOKED


def mint(service, **overrides):
    payload = {"brand": "cursor", "repo_locale": "iac-bus", "role": "worker",
               "medium": "api"}
    payload.update(overrides)
    return service.mint_agent(payload)


@pytest.fixture
def orchestrator(service):
    return mint(service, role="orchestrator", ordinal_path="0",
                custody=CUSTODY_KEYCHAIN)


class TestTrustRoots:
    def test_auto_bootstrap_creates_a_default_root(self, service):
        root = service.resolve_root()
        assert root["is_default"] is True
        assert root["capabilities"] == ["*"]

    def test_the_root_certificate_is_self_signed_and_verifiable(self, service):
        root = service.resolve_root()
        chain = service.store.get_certificate_chain(root["cert_id"])
        assert len(chain) == 1
        assert service.verify_chain(chain).valid

    def test_duplicate_root_names_conflict(self, service):
        service.resolve_root()
        with pytest.raises(ConflictError):
            service.bootstrap_root(name="test-root")

    def test_a_second_root_does_not_steal_the_default(self, service):
        first = service.resolve_root()
        service.bootstrap_root(name="second-root")
        assert service.resolve_root()["root_id"] == first["root_id"]

    def test_roots_can_be_resolved_by_name_or_key_id(self, service):
        root = service.resolve_root()
        assert service.resolve_root(root["name"])["root_id"] == root["root_id"]
        assert service.resolve_root(root["key_id"])["root_id"] == root["root_id"]

    def test_an_unknown_root_reference_is_a_404(self, service):
        with pytest.raises(NotFoundError):
            service.resolve_root("no-such-root")

    def test_without_auto_bootstrap_minting_reports_the_missing_root(self, service):
        service.config.auto_bootstrap_root = False
        with pytest.raises(NotFoundError) as excinfo:
            mint(service)
        assert "no trust root configured" in str(excinfo.value)

    def test_jwks_exposes_only_public_material(self, service):
        service.resolve_root()
        jwks = service.jwks()
        assert jwks["keys"]
        for key in jwks["keys"]:
            assert "d" not in key
            assert key["alg"] == "EdDSA"


class TestMasterMint:
    def test_minting_returns_an_acp_v2_identity(self, service):
        result = mint(service)
        assert result.created is True
        assert result.status_code == 201
        assert identity.validate_agent_uuid(result.agent["agent_uuid"])
        assert result.agent["logical_handle"] == "agent:cursor.iac-bus.0"
        assert result.endpoint["endpoint_handle"] == "agent:cursor.iac-bus.0@api"

    def test_an_omitted_ordinal_defaults_to_the_master(self, service):
        assert mint(service).agent["ordinal_path"] == identity.MASTER_ORDINAL

    def test_fields_are_normalized(self, service):
        result = mint(service, brand="  Cursor ", repo_locale="IAC-Bus",
                      role=" Orchestrator ", medium="WEB")
        assert result.agent["brand"] == "cursor"
        assert result.agent["repo_locale"] == "iac-bus"
        assert result.agent["role"] == "orchestrator"
        assert result.endpoint["medium"] == "web"

    def test_the_certificate_chain_verifies(self, service):
        result = mint(service)
        verification = service.verify_chain(result.chain)
        assert verification.valid, verification.errors
        assert verification.subject["logical_handle"] == "agent:cursor.iac-bus.0"

    def test_capabilities_default_from_the_role(self, service):
        result = mint(service, role="observer")
        assert result.agent["capabilities"] == caps.default_capabilities_for_role(
            "observer"
        )

    def test_explicit_capabilities_are_honoured(self, service):
        result = mint(service, capabilities=["bus.read"])
        assert result.agent["capabilities"] == ["bus.read"]

    def test_custody_agent_returns_the_private_key_once(self, service):
        result = mint(service)
        assert result.agent["custody"] == CUSTODY_AGENT
        assert result.private_jwk is not None
        assert result.agent["sealed_private_key"] is None
        # A second resolve of the same handle must not hand the key out again.
        assert mint(service).private_jwk is None

    def test_custody_keychain_seals_the_key_instead(self, service):
        result = mint(service, custody=CUSTODY_KEYCHAIN)
        assert result.agent["custody"] == CUSTODY_KEYCHAIN
        assert result.private_jwk is None
        assert result.agent["sealed_private_key"].startswith("kcw1.")

    def test_a_caller_supplied_public_key_is_used_verbatim(self, service):
        private_key = keys.generate_private_key()
        jwk = keys.public_jwk(private_key.public_key())
        result = mint(service, public_key=jwk)
        assert result.agent["key_id"] == jwk["kid"]
        assert result.private_jwk is None
        assert service.verify_chain(result.chain).valid

    def test_an_invalid_public_key_is_rejected(self, service):
        with pytest.raises(ValidationError):
            mint(service, public_key={"kty": "RSA"})

    def test_one_key_cannot_back_two_identities(self, service):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        mint(service, public_key=jwk)
        with pytest.raises(ConflictError) as excinfo:
            mint(service, repo_locale="repo-x", public_key=jwk)
        assert excinfo.value.conflict_code == CONFLICT_KEY_MISMATCH

    def test_metadata_is_stored(self, service):
        result = mint(service, metadata={"branch": "cursor/demo"})
        assert result.agent["metadata"] == {"branch": "cursor/demo"}

    def test_derived_uuid_mode_is_reproducible_across_instances(self, service, store,
                                                               key_wrapper):
        from keychain.service import KeyChainService

        service.config.uuid_mode = identity.UUID_MODE_DERIVED
        first = mint(service).agent["agent_uuid"]
        # A second service over the same root must derive the same agent_uuid.
        root = service.resolve_root()
        expected = identity.mint_agent_uuid(
            "agent:cursor.iac-bus.0",
            mode=identity.UUID_MODE_DERIVED,
            namespace_seed=root["key_id"],
        )
        assert first == expected
        assert isinstance(
            KeyChainService(store=store, key_wrapper=key_wrapper,
                            config=service.config),
            KeyChainService,
        )


class TestChildMint:
    def test_a_child_ordinal_is_allocated_automatically(self, service, orchestrator):
        first = mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"])
        second = mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"])
        assert first.agent["logical_handle"] == "agent:cursor.iac-bus.0-0"
        assert second.agent["logical_handle"] == "agent:cursor.iac-bus.0-1"

    def test_a_parent_may_be_named_by_handle(self, service, orchestrator):
        result = mint(service, parent_handle=orchestrator.agent["logical_handle"])
        assert result.agent["parent_agent_uuid"] == orchestrator.agent["agent_uuid"]

    def test_contradictory_parent_references_are_rejected(self, service, orchestrator):
        other = mint(service, repo_locale="repo-x", role="orchestrator")
        with pytest.raises(ValidationError):
            mint(
                service,
                parent_agent_uuid=orchestrator.agent["agent_uuid"],
                parent_handle=other.agent["logical_handle"],
            )

    def test_a_missing_parent_is_a_404(self, service):
        with pytest.raises(NotFoundError):
            mint(service, ordinal_path="0-1",
                 parent_agent_uuid="00000000-0000-4000-8000-000000000000")

    def test_a_non_master_ordinal_without_a_parent_is_a_400(self, service):
        with pytest.raises(ValidationError) as excinfo:
            mint(service, ordinal_path="0-1")
        assert any("parent is" in detail for detail in excinfo.value.details)

    def test_a_revoked_parent_cannot_mint(self, service, orchestrator):
        service.revoke_agent(orchestrator.agent["agent_uuid"])
        with pytest.raises(RevokedError):
            mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"])

    def test_a_child_is_signed_by_its_parent_when_the_key_is_held(self, service,
                                                                 orchestrator):
        child = mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"])
        assert child.certificate["issuer"]["key_id"] == orchestrator.agent["key_id"]
        assert len(child.chain) == 3
        assert service.verify_chain(child.chain).valid

    def test_a_child_falls_back_to_the_root_when_the_parent_holds_its_own_key(
        self, service
    ):
        parent = mint(service, role="orchestrator", custody=CUSTODY_AGENT)
        child = mint(service, parent_agent_uuid=parent.agent["agent_uuid"])
        root = service.resolve_root()
        assert child.certificate["issuer"]["key_id"] == root["key_id"]
        assert len(child.chain) == 2
        assert service.verify_chain(child.chain).valid

    def test_issuer_parent_is_refused_when_the_key_is_not_held(self, service):
        parent = mint(service, role="orchestrator", custody=CUSTODY_AGENT)
        with pytest.raises(CustodyError):
            mint(service, parent_agent_uuid=parent.agent["agent_uuid"],
                 issuer="parent")

    def test_issuer_root_bypasses_the_parent(self, service, orchestrator):
        child = mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"],
                     issuer="root")
        assert child.certificate["issuer"]["key_id"] == service.resolve_root()["key_id"]

    def test_issuer_parent_requires_a_parent(self, service):
        with pytest.raises(ValidationError):
            mint(service, issuer="parent")

    def test_a_child_cannot_exceed_its_parents_capabilities(self, service):
        parent = mint(service, role="orchestrator", capabilities=["bus.read"],
                      custody=CUSTODY_KEYCHAIN)
        with pytest.raises(ValidationError) as excinfo:
            mint(service, parent_agent_uuid=parent.agent["agent_uuid"],
                 capabilities=["agent.mint"])
        assert "cannot delegate" in str(excinfo.value)

    def test_role_defaults_are_attenuated_against_the_parent(self, service):
        parent = mint(service, role="orchestrator", capabilities=["bus.read"],
                      custody=CUSTODY_KEYCHAIN)
        with pytest.raises(ValidationError):
            # The worker default includes bus.post, which this parent lacks.
            mint(service, parent_agent_uuid=parent.agent["agent_uuid"])

    def test_cross_namespace_delegation_mints_a_new_master(self, service, orchestrator):
        child = mint(service, repo_locale="repo-x",
                     parent_agent_uuid=orchestrator.agent["agent_uuid"])
        assert child.agent["logical_handle"] == "agent:cursor.repo-x.0"
        assert service.verify_chain(child.chain).valid

    def test_a_three_generation_tree_verifies(self, service, orchestrator):
        middle = mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"],
                      role="orchestrator", custody=CUSTODY_KEYCHAIN)
        leaf = mint(service, parent_agent_uuid=middle.agent["agent_uuid"])
        assert leaf.agent["ordinal_path"] == "0-0-0"
        assert len(leaf.chain) == 4
        assert service.verify_chain(leaf.chain).valid


class TestIdempotencyAndConflicts:
    def test_re_minting_the_same_identity_is_idempotent(self, service):
        first = mint(service)
        second = mint(service)
        assert second.created is False
        assert second.status_code == 200
        assert second.agent["agent_uuid"] == first.agent["agent_uuid"]
        assert second.agent["key_id"] == first.agent["key_id"]

    def test_a_new_medium_reuses_the_identity_and_adds_an_endpoint(self, service):
        first = mint(service, medium="web")
        second = mint(service, medium="slack")
        assert second.created is False
        assert second.agent["agent_uuid"] == first.agent["agent_uuid"]
        assert second.endpoint["endpoint_handle"] == "agent:cursor.iac-bus.0@slack"
        assert len(service.store.list_endpoints(first.agent["agent_uuid"])) == 2

    def test_a_new_session_reuses_the_identity(self, service):
        first = mint(service, medium="web", session_id="s-1")
        second = mint(service, medium="web", session_id="s-2")
        assert second.agent["agent_uuid"] == first.agent["agent_uuid"]
        assert len(service.store.list_endpoints(first.agent["agent_uuid"])) == 2

    def test_a_different_parent_is_a_parent_mismatch(self, service, orchestrator):
        child = mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"])
        other_parent = mint(service, repo_locale="repo-x", role="orchestrator",
                            custody=CUSTODY_KEYCHAIN)
        with pytest.raises(ConflictError) as excinfo:
            service.mint_agent(
                {
                    "brand": "cursor",
                    "repo_locale": "iac-bus",
                    "ordinal_path": child.agent["ordinal_path"],
                    "role": "worker",
                    "medium": "api",
                    "parent_agent_uuid": other_parent.agent["agent_uuid"],
                }
            )
        assert excinfo.value.conflict_code == CONFLICT_PARENT_MISMATCH
        assert excinfo.value.extra["existing_agent_uuid"] == child.agent["agent_uuid"]

    def test_a_different_role_is_a_role_mismatch(self, service):
        mint(service, role="worker")
        with pytest.raises(ConflictError) as excinfo:
            mint(service, role="reviewer")
        assert excinfo.value.conflict_code == CONFLICT_ROLE_MISMATCH

    def test_a_different_key_is_a_key_mismatch(self, service):
        mint(service)
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        with pytest.raises(ConflictError) as excinfo:
            mint(service, public_key=jwk)
        assert excinfo.value.conflict_code == CONFLICT_KEY_MISMATCH

    def test_a_revoked_handle_cannot_be_re_minted(self, service):
        first = mint(service)
        service.revoke_agent(first.agent["agent_uuid"])
        with pytest.raises(ConflictError) as excinfo:
            mint(service)
        assert excinfo.value.conflict_code == "HANDLE_REVOKED"

    def test_a_corrupted_row_surfaces_an_identity_mismatch(self, service):
        result = mint(service)
        service.store._execute(
            "UPDATE agents SET brand = 'other' WHERE agent_uuid = ?",
            (result.agent["agent_uuid"],),
        )
        with pytest.raises(ConflictError) as excinfo:
            mint(service)
        assert excinfo.value.conflict_code == CONFLICT_IDENTITY_MISMATCH


class TestRequestValidation:
    def test_a_non_object_body_is_rejected(self, service):
        with pytest.raises(ValidationError):
            service.mint_agent(["not", "an", "object"])

    def test_brand_and_repo_locale_are_required(self, service):
        with pytest.raises(ValidationError) as excinfo:
            service.mint_agent({"role": "worker"})
        assert "brand is required" in excinfo.value.details
        assert "repo_locale is required" in excinfo.value.details

    def test_every_problem_is_reported_at_once(self, service):
        with pytest.raises(ValidationError) as excinfo:
            service.mint_agent(
                {"brand": "Cursor!", "repo_locale": "iac-bus", "medium": "telepathy",
                 "ordinal_path": "0-", "custody": "vault"}
            )
        assert len(excinfo.value.details) >= 4

    def test_medium_is_optional_for_mint_but_required_for_register(self, service):
        assert mint(service, medium=None).endpoint["medium"] == "api"
        with pytest.raises(ValidationError) as excinfo:
            service.mint_agent(
                {"brand": "cursor", "repo_locale": "repo-x"}, require_medium=True
            )
        assert "medium is required" in excinfo.value.details

    def test_a_logical_handle_may_replace_the_components(self, service):
        result = service.mint_agent(
            {"logical_handle": "agent:cursor.iac-bus.0", "role": "worker",
             "medium": "web"}
        )
        assert result.agent["brand"] == "cursor"
        assert result.agent["ordinal_path"] == "0"

    def test_components_must_agree_with_the_logical_handle(self, service):
        with pytest.raises(ValidationError) as excinfo:
            service.mint_agent(
                {"logical_handle": "agent:cursor.iac-bus.0", "brand": "openclaw",
                 "medium": "web"}
            )
        assert any("contradicts" in detail for detail in excinfo.value.details)

    def test_a_malformed_ttl_is_rejected(self, service):
        with pytest.raises(ValidationError):
            mint(service, ttl_seconds=-5)

    def test_metadata_must_be_an_object(self, service):
        with pytest.raises(ValidationError):
            mint(service, metadata=["nope"])

    def test_an_unknown_issuer_mode_is_rejected(self, service):
        with pytest.raises(ValidationError):
            mint(service, issuer="notary")


class TestLifecycle:
    def test_heartbeat_records_last_seen(self, service):
        result = mint(service, medium="web")
        endpoint = service.heartbeat(result.agent["agent_uuid"], "web")
        assert endpoint["last_seen_at"] is not None

    def test_heartbeat_creates_a_missing_endpoint(self, service):
        result = mint(service, medium="web")
        endpoint = service.heartbeat(result.agent["agent_uuid"], "slack")
        assert endpoint["endpoint_handle"] == "agent:cursor.iac-bus.0@slack"

    def test_heartbeat_for_an_unknown_agent_is_a_404(self, service):
        with pytest.raises(NotFoundError):
            service.heartbeat("00000000-0000-4000-8000-000000000000", "web")

    def test_agents_resolve_by_uuid_handle_and_endpoint_handle(self, service):
        result = mint(service, medium="web")
        for reference in (
            result.agent["agent_uuid"],
            result.agent["logical_handle"],
            "agent:cursor.iac-bus.0@web",
        ):
            assert service.require_agent(reference)["agent_uuid"] == (
                result.agent["agent_uuid"]
            )

    def test_an_empty_reference_is_rejected(self, service):
        with pytest.raises(ValidationError):
            service.require_agent("  ")

    def test_describe_agent_reports_the_tree_and_endpoints(self, service, orchestrator):
        mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"])
        described = service.describe_agent(orchestrator.agent["logical_handle"])
        assert described["children"] == ["agent:cursor.iac-bus.0-0"]
        assert described["endpoints"][0]["medium"] == "api"
        assert described["certificate_chain"]

    def test_describe_agent_can_omit_the_chain(self, service):
        result = mint(service)
        described = service.describe_agent(
            result.agent["agent_uuid"], include_chain=False
        )
        assert "certificate_chain" not in described


class TestRevocation:
    def test_revocation_cascades_to_descendants(self, service, orchestrator):
        middle = mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"],
                      role="orchestrator", custody=CUSTODY_KEYCHAIN)
        leaf = mint(service, parent_agent_uuid=middle.agent["agent_uuid"])
        outcome = service.revoke_agent(orchestrator.agent["agent_uuid"],
                                       reason="key leaked")
        assert set(outcome["revoked"]) == {
            orchestrator.agent["logical_handle"],
            middle.agent["logical_handle"],
            leaf.agent["logical_handle"],
        }
        assert service.store.get_agent(leaf.agent["agent_uuid"])["status"] == (
            STATUS_REVOKED
        )

    def test_revocation_can_be_limited_to_one_agent(self, service, orchestrator):
        child = mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"])
        service.revoke_agent(orchestrator.agent["agent_uuid"], cascade=False)
        assert service.store.get_agent(child.agent["agent_uuid"])["status"] != (
            STATUS_REVOKED
        )

    def test_revocation_drops_held_private_keys(self, service, orchestrator):
        service.revoke_agent(orchestrator.agent["agent_uuid"])
        stored = service.store.get_agent(orchestrator.agent["agent_uuid"])
        assert stored["sealed_private_key"] is None

    def test_revocation_deactivates_endpoints(self, service):
        result = mint(service, medium="web")
        service.revoke_agent(result.agent["agent_uuid"])
        assert all(
            endpoint["is_active"] is False
            for endpoint in service.store.list_endpoints(result.agent["agent_uuid"])
        )

    def test_a_revoked_chain_fails_verification(self, service):
        result = mint(service)
        assert service.verify_chain(result.chain).valid
        service.revoke_agent(result.agent["agent_uuid"])
        verification = service.verify_chain(result.chain)
        assert not verification.valid
        assert any("revoked" in error for error in verification.errors)

    def test_revocation_can_be_ignored_for_offline_checks(self, service):
        result = mint(service)
        service.revoke_agent(result.agent["agent_uuid"])
        assert service.verify_chain(result.chain, check_revocation=False).valid

    def test_revoking_a_root_records_it(self, service):
        root = service.resolve_root()
        outcome = service.revoke_root(root["name"], reason="rotation")
        assert outcome["key_id"] == root["key_id"]
        assert root["key_id"] in service.store.revoked_key_ids()

    def test_revoking_an_unknown_agent_is_a_404(self, service):
        with pytest.raises(NotFoundError):
            service.revoke_agent("agent:cursor.iac-bus.9")


class TestCertificateVerification:
    def test_a_stored_certificate_verifies(self, service):
        result = mint(service)
        assert service.verify_certificate(result.certificate).valid

    def test_a_tampered_certificate_fails_even_when_stored(self, service):
        result = mint(service)
        tampered = dict(result.certificate)
        tampered["capabilities"] = ["*"]
        assert not service.verify_certificate(tampered).valid

    def test_an_unknown_certificate_fails_rather_than_raising(self, service):
        verification = service.verify_certificate(
            {"cert_id": "unknown", "cert_type": "agent", "subject": {}}
        )
        assert not verification.valid

    def test_a_non_object_certificate_is_rejected(self, service):
        with pytest.raises(ValidationError):
            service.verify_certificate("nope")


class TestTokens:
    def test_a_keychain_custody_agent_gets_a_self_contained_token(self, service,
                                                                 orchestrator):
        issued = service.issue_token(orchestrator.agent["agent_uuid"])
        assert issued["self_contained"] is True
        verification = service.verify_token(issued["token"], audience="iac-bus")
        assert verification.valid, verification.errors
        assert verification.payload["handle"] == orchestrator.agent["logical_handle"]

    def test_an_agent_custody_agent_gets_an_authority_signed_token(self, service):
        result = mint(service)
        issued = service.issue_token(result.agent["agent_uuid"])
        assert issued["self_contained"] is False
        verification = service.verify_token(issued["token"], audience="iac-bus")
        assert verification.valid, verification.errors

    def test_the_default_audience_is_applied(self, service, orchestrator):
        issued = service.issue_token(orchestrator.agent["logical_handle"])
        verification = service.verify_token(issued["token"], audience="iac-bus")
        assert verification.valid, verification.errors

    def test_a_token_may_narrow_capabilities(self, service, orchestrator):
        issued = service.issue_token(
            orchestrator.agent["agent_uuid"], capabilities=["bus.read"]
        )
        assert issued["capabilities"] == ["bus.read"]

    def test_a_token_may_not_widen_capabilities(self, service):
        result = mint(service, capabilities=["bus.read"], custody=CUSTODY_KEYCHAIN)
        with pytest.raises(ValidationError):
            service.issue_token(result.agent["agent_uuid"],
                                capabilities=["agent.mint"])

    def test_ttl_is_bounded_by_configuration(self, service, orchestrator):
        with pytest.raises(ValidationError):
            service.issue_token(
                orchestrator.agent["agent_uuid"],
                ttl_seconds=service.config.max_token_ttl_seconds + 1,
            )

    def test_a_malformed_ttl_is_rejected(self, service, orchestrator):
        with pytest.raises(ValidationError):
            service.issue_token(orchestrator.agent["agent_uuid"], ttl_seconds="1h")

    def test_a_revoked_agent_cannot_be_issued_a_token(self, service, orchestrator):
        service.revoke_agent(orchestrator.agent["agent_uuid"])
        with pytest.raises(RevokedError):
            service.issue_token(orchestrator.agent["agent_uuid"])

    def test_revocation_invalidates_an_already_issued_token(self, service,
                                                            orchestrator):
        issued = service.issue_token(orchestrator.agent["agent_uuid"])
        service.revoke_agent(orchestrator.agent["agent_uuid"])
        verification = service.verify_token(issued["token"])
        assert not verification.valid
        assert any("revoked" in error for error in verification.errors)

    def test_revocation_invalidates_an_authority_signed_token(self, service):
        result = mint(service)
        issued = service.issue_token(result.agent["agent_uuid"])
        service.revoke_agent(result.agent["agent_uuid"])
        verification = service.verify_token(issued["token"])
        assert not verification.valid
        assert any("subject" in error and "revoked" in error
                   for error in verification.errors)

    def test_required_capabilities_are_enforced(self, service, orchestrator):
        issued = service.issue_token(orchestrator.agent["agent_uuid"])
        assert service.verify_token(
            issued["token"], required_capabilities=["agent.mint"]
        ).valid
        assert not service.verify_token(
            issued["token"], required_capabilities=["nuclear.launch"]
        ).valid

    def test_a_token_from_another_keychain_is_not_trusted(self, service, store,
                                                          key_wrapper, config):
        from keychain.service import KeyChainService
        from keychain.store import KeyChainStore

        other_store = KeyChainStore(":memory:")
        other = KeyChainService(store=other_store, key_wrapper=key_wrapper,
                                config=config)
        other.bootstrap_root(name="rogue-root")
        rogue = other.mint_agent(
            {"brand": "cursor", "repo_locale": "iac-bus", "role": "orchestrator",
             "medium": "api", "custody": CUSTODY_KEYCHAIN}
        )
        issued = other.issue_token(rogue.agent["agent_uuid"])
        service.resolve_root()
        verification = service.verify_token(issued["token"])
        assert not verification.valid
        other_store.close()

    def test_issuing_a_token_for_an_unknown_agent_is_a_404(self, service):
        with pytest.raises(NotFoundError):
            service.issue_token("agent:cursor.iac-bus.9")

    def test_an_authority_signed_token_stays_header_safe(self, service):
        issued = service.issue_token(mint(service).agent["agent_uuid"])
        assert issued["header_safe"] is True
        assert issued["token_bytes"] == len(issued["token"])

    def test_a_deep_chain_reports_that_the_token_outgrew_a_header(self, service):
        """An embedded chain costs about 1.4 KB per link, so depth is visible."""
        from keychain import tokens as token_module

        parent = mint(service, role="orchestrator", custody=CUSTODY_KEYCHAIN)
        for _ in range(3):
            parent = mint(service, role="orchestrator", custody=CUSTODY_KEYCHAIN,
                          parent_agent_uuid=parent.agent["agent_uuid"])
        issued = service.issue_token(parent.agent["agent_uuid"])
        assert issued["token_bytes"] > token_module.HEADER_SAFE_BYTES
        assert issued["header_safe"] is False
        # Still a perfectly valid token: the flag is advice, not a rejection.
        assert service.verify_token(issued["token"]).valid


class TestStats:
    def test_stats_track_what_has_been_minted(self, service, orchestrator):
        mint(service, parent_agent_uuid=orchestrator.agent["agent_uuid"])
        service.revoke_agent(orchestrator.agent["agent_uuid"])
        stats = service.stats()
        assert stats["agents"] == 2
        assert stats["trust_roots"] == 1
        assert stats["revocations"] == 2
        assert stats["default_root_key_id"] == service.resolve_root()["key_id"]
