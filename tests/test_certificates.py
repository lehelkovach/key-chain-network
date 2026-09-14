"""Certificate issuance and chain-of-trust verification."""

import copy
import datetime

import pytest

from keychain import capabilities as caps
from keychain import certificates, identity, keys
from keychain.canonical import to_iso8601, utcnow
from keychain.errors import SignatureError, TrustError, ValidationError


def make_root(name="test-root", capabilities=caps.ROOT_CAPABILITIES,
              issued_at=None, expires_at=None):
    issued_at = issued_at or utcnow()
    if expires_at is None:
        expires_at = issued_at + datetime.timedelta(days=365)
    private_key = keys.generate_private_key()
    jwk = keys.public_jwk(private_key.public_key())
    subject = certificates.build_root_subject("root-uuid-%s" % name, name, jwk)
    certificate = certificates.issue_certificate(
        certificates.CERT_TYPE_ROOT,
        subject,
        capabilities,
        private_key,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return private_key, certificate


def make_agent(signing_key, issuer_certificate, handle, role="worker",
               capabilities=("bus.post", "bus.read"), parent_agent_uuid=None,
               issued_at=None, expires_at=None, agent_uuid=None):
    private_key = keys.generate_private_key()
    jwk = keys.public_jwk(private_key.public_key())
    subject = certificates.build_agent_subject(
        agent_uuid or identity.mint_agent_uuid(handle),
        handle,
        role,
        jwk,
        parent_agent_uuid=parent_agent_uuid,
    )
    certificate = certificates.issue_certificate(
        certificates.CERT_TYPE_AGENT,
        subject,
        capabilities,
        signing_key,
        issuer_certificate=issuer_certificate,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return private_key, certificate


@pytest.fixture
def root_pair():
    return make_root()


class TestIssuance:
    def test_root_certificate_is_self_signed(self, root_pair):
        _private_key, certificate = root_pair
        assert certificate["cert_type"] == certificates.CERT_TYPE_ROOT
        assert certificate["issuer"]["self_signed"] is True
        assert certificate["issuer"]["cert_id"] is None
        assert certificate["issuer"]["key_id"] == certificate["subject"]["key_id"]

    def test_root_must_be_signed_by_its_own_key(self):
        _key, root_certificate = make_root()
        with pytest.raises(ValidationError):
            certificates.issue_certificate(
                certificates.CERT_TYPE_ROOT,
                root_certificate["subject"],
                ["*"],
                keys.generate_private_key(),
            )

    def test_agent_certificate_may_not_be_self_signed(self, root_pair):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        subject = certificates.build_agent_subject(
            identity.mint_agent_uuid("agent:cursor.iac-bus.0"),
            "agent:cursor.iac-bus.0",
            "worker",
            jwk,
        )
        with pytest.raises(ValidationError):
            certificates.issue_certificate(
                certificates.CERT_TYPE_AGENT, subject, [], root_pair[0]
            )

    def test_agent_certificate_records_its_issuer(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0", role="orchestrator"
        )
        assert certificate["issuer"]["cert_id"] == root_certificate["cert_id"]
        assert certificate["issuer"]["key_id"] == root_certificate["subject"]["key_id"]
        assert certificate["issuer"]["self_signed"] is False

    def test_subject_is_derived_from_the_handle(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.repo.x.0-4-8"
        )
        subject = certificate["subject"]
        assert subject["brand"] == "cursor"
        assert subject["repo_locale"] == "repo.x"
        assert subject["ordinal_path"] == "0-4-8"

    def test_signing_key_must_match_the_issuer_certificate(self, root_pair):
        _root_key, root_certificate = root_pair
        with pytest.raises(ValidationError):
            make_agent(
                keys.generate_private_key(),
                root_certificate,
                "agent:cursor.iac-bus.0",
            )

    def test_expiry_is_clamped_to_the_issuer(self):
        issued_at = utcnow()
        root_key, root_certificate = make_root(
            issued_at=issued_at, expires_at=issued_at + datetime.timedelta(days=10)
        )
        _key, certificate = make_agent(
            root_key,
            root_certificate,
            "agent:cursor.iac-bus.0",
            issued_at=issued_at,
            expires_at=issued_at + datetime.timedelta(days=365),
        )
        assert certificate["expires_at"] == root_certificate["expires_at"]

    def test_unknown_cert_type_is_rejected(self, root_pair):
        with pytest.raises(ValidationError):
            certificates.issue_certificate("intermediate", {}, [], root_pair[0])


class TestSignatureCoverage:
    def test_signature_verifies_against_the_issuer_key(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        assert certificates.verify_signature(
            certificate, root_certificate["subject"]["public_key"]
        )

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda cert: cert["subject"].update(role="orchestrator"),
            lambda cert: cert["subject"].update(logical_handle="agent:cursor.iac-bus.1"),
            lambda cert: cert.update(capabilities=["*"]),
            lambda cert: cert.update(expires_at=None),
            lambda cert: cert["issuer"].update(subject_ref="root:other"),
        ],
    )
    def test_any_edit_breaks_the_signature(self, root_pair, mutate):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        tampered = copy.deepcopy(certificate)
        mutate(tampered)
        with pytest.raises(SignatureError):
            certificates.verify_signature(
                tampered, root_certificate["subject"]["public_key"]
            )

    def test_added_fields_break_the_signature(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        certificate["surprise"] = "extra claim"
        with pytest.raises(SignatureError):
            certificates.verify_signature(
                certificate, root_certificate["subject"]["public_key"]
            )

    def test_wrong_issuer_key_is_reported_as_a_key_id_mismatch(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        other = keys.public_jwk(keys.generate_private_key().public_key())
        with pytest.raises(SignatureError):
            certificates.verify_signature(certificate, other)

    def test_unsupported_algorithm_is_rejected(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        certificate["signature"]["alg"] = "RS256"
        with pytest.raises(ValidationError):
            certificates.verify_signature(
                certificate, root_certificate["subject"]["public_key"]
            )


class TestChainVerification:
    def test_a_root_only_chain_verifies(self, root_pair):
        _key, root_certificate = root_pair
        result = certificates.verify_chain(
            [root_certificate], [root_certificate["subject"]["key_id"]]
        )
        assert result.valid, result.errors

    def test_a_two_link_chain_verifies(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        result = certificates.verify_chain(
            [certificate, root_certificate], [root_certificate["subject"]["key_id"]]
        )
        assert result.valid, result.errors
        assert result.chain_length == 2
        assert result.subject["logical_handle"] == "agent:cursor.iac-bus.0"
        assert result.root_key_id == root_certificate["subject"]["key_id"]

    def test_a_three_link_delegation_chain_verifies(self, root_pair):
        root_key, root_certificate = root_pair
        orchestrator_key, orchestrator = make_agent(
            root_key,
            root_certificate,
            "agent:cursor.iac-bus.0",
            role="orchestrator",
            capabilities=("agent.mint", "bus.post", "bus.read"),
        )
        _worker_key, worker = make_agent(
            orchestrator_key,
            orchestrator,
            "agent:cursor.iac-bus.0-1",
            capabilities=("bus.read",),
            parent_agent_uuid=orchestrator["subject"]["agent_uuid"],
        )
        result = certificates.verify_chain(
            [worker, orchestrator, root_certificate],
            [root_certificate["subject"]["key_id"]],
        )
        assert result.valid, result.errors
        assert result.capabilities == ["bus.read"]

    def test_an_untrusted_root_is_rejected(self, root_pair):
        _key, root_certificate = root_pair
        result = certificates.verify_chain([root_certificate], ["some-other-root"])
        assert not result.valid
        assert any("not trusted" in error for error in result.errors)

    def test_a_chain_must_end_in_a_root(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        result = certificates.verify_chain([certificate], ["anything"])
        assert not result.valid
        assert any("terminate in a root" in error for error in result.errors)

    def test_a_broken_link_is_reported(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        _other_key, other_root = make_root(name="other-root")
        result = certificates.verify_chain(
            [certificate, other_root], [other_root["subject"]["key_id"]]
        )
        assert not result.valid
        assert any("issuer key_id mismatch" in error for error in result.errors)

    def test_capability_escalation_is_rejected(self, root_pair):
        root_key, root_certificate = root_pair
        orchestrator_key, orchestrator = make_agent(
            root_key,
            root_certificate,
            "agent:cursor.iac-bus.0",
            role="orchestrator",
            capabilities=("bus.read",),
        )
        # Forge a child that grants itself more than its issuer holds.
        _worker_key, worker = make_agent(
            orchestrator_key,
            orchestrator,
            "agent:cursor.iac-bus.0-1",
            capabilities=("agent.mint",),
            parent_agent_uuid=orchestrator["subject"]["agent_uuid"],
        )
        result = certificates.verify_chain(
            [worker, orchestrator, root_certificate],
            [root_certificate["subject"]["key_id"]],
        )
        assert not result.valid
        assert any("cannot delegate" in error for error in result.errors)

    def test_ordinal_path_must_be_a_direct_child_in_the_same_namespace(self, root_pair):
        root_key, root_certificate = root_pair
        orchestrator_key, orchestrator = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0",
            role="orchestrator", capabilities=("bus.read",),
        )
        _key, impostor = make_agent(
            orchestrator_key,
            orchestrator,
            "agent:cursor.iac-bus.9-9",
            capabilities=("bus.read",),
        )
        result = certificates.verify_chain(
            [impostor, orchestrator, root_certificate],
            [root_certificate["subject"]["key_id"]],
        )
        assert not result.valid
        assert any("not a direct child" in error for error in result.errors)

    def test_cross_namespace_delegation_needs_no_ordinal_relationship(self, root_pair):
        root_key, root_certificate = root_pair
        orchestrator_key, orchestrator = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0",
            role="orchestrator", capabilities=("bus.read",),
        )
        _key, other_repo_master = make_agent(
            orchestrator_key,
            orchestrator,
            "agent:cursor.repo-x.0",
            capabilities=("bus.read",),
        )
        result = certificates.verify_chain(
            [other_repo_master, orchestrator, root_certificate],
            [root_certificate["subject"]["key_id"]],
        )
        assert result.valid, result.errors

    def test_a_declared_parent_must_match_the_signer(self, root_pair):
        root_key, root_certificate = root_pair
        orchestrator_key, orchestrator = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0",
            role="orchestrator", capabilities=("bus.read",),
        )
        _key, worker = make_agent(
            orchestrator_key,
            orchestrator,
            "agent:cursor.iac-bus.0-1",
            capabilities=("bus.read",),
            parent_agent_uuid=identity.mint_agent_uuid("agent:cursor.iac-bus.0"),
        )
        result = certificates.verify_chain(
            [worker, orchestrator, root_certificate],
            [root_certificate["subject"]["key_id"]],
        )
        assert not result.valid
        assert any("declares parent" in error for error in result.errors)

    def test_an_expired_certificate_is_rejected(self):
        long_ago = utcnow() - datetime.timedelta(days=30)
        root_key, root_certificate = make_root(
            issued_at=long_ago, expires_at=long_ago + datetime.timedelta(days=1)
        )
        result = certificates.verify_chain(
            [root_certificate], [root_certificate["subject"]["key_id"]]
        )
        assert not result.valid
        assert any("expired" in error for error in result.errors)

    def test_a_future_dated_certificate_is_rejected(self):
        soon = utcnow() + datetime.timedelta(days=1)
        _key, root_certificate = make_root(issued_at=soon)
        result = certificates.verify_chain(
            [root_certificate], [root_certificate["subject"]["key_id"]]
        )
        assert not result.valid
        assert any("not yet valid" in error for error in result.errors)

    def test_a_child_may_not_outlive_its_issuer(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        # Re-sign a longer-lived copy so only the nesting rule can catch it.
        forged = copy.deepcopy(certificate)
        forged["expires_at"] = to_iso8601(utcnow() + datetime.timedelta(days=3650))
        forged["signature"]["value"] = keys.sign(
            root_key, certificates.signing_payload(forged)
        )
        result = certificates.verify_chain(
            [forged, root_certificate], [root_certificate["subject"]["key_id"]]
        )
        assert not result.valid
        assert any("outlives its issuer" in error for error in result.errors)

    def test_revocation_callback_is_honoured(self, root_pair):
        root_key, root_certificate = root_pair
        _key, certificate = make_agent(
            root_key, root_certificate, "agent:cursor.iac-bus.0"
        )
        result = certificates.verify_chain(
            [certificate, root_certificate],
            [root_certificate["subject"]["key_id"]],
            is_revoked=lambda cert: cert["cert_id"] == certificate["cert_id"],
        )
        assert not result.valid
        assert any("revoked" in error for error in result.errors)

    def test_every_problem_is_collected(self, root_pair):
        _key, root_certificate = root_pair
        tampered = copy.deepcopy(root_certificate)
        tampered["capabilities"] = ["bus.read"]
        result = certificates.verify_chain(tampered and [tampered], ["untrusted"])
        assert len(result.errors) >= 2

    def test_an_empty_chain_is_rejected(self):
        assert not certificates.verify_chain([], ["root"]).valid

    def test_an_over_long_chain_is_rejected(self, root_pair):
        _key, root_certificate = root_pair
        chain = [root_certificate] * (certificates.MAX_CHAIN_DEPTH + 1)
        result = certificates.verify_chain(chain, [root_certificate["subject"]["key_id"]])
        assert not result.valid
        assert any("exceeds maximum" in error for error in result.errors)

    def test_raise_for_status_raises_on_failure(self):
        with pytest.raises(TrustError):
            certificates.verify_chain([], ["root"]).raise_for_status()

    def test_raise_for_status_returns_self_on_success(self, root_pair):
        _key, root_certificate = root_pair
        result = certificates.verify_chain(
            [root_certificate], [root_certificate["subject"]["key_id"]]
        )
        assert result.raise_for_status() is result
