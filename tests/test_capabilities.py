"""Capability grammar and attenuation rules."""

import pytest

from keychain import capabilities as caps
from keychain.errors import ValidationError


class TestNormalization:
    def test_normalization_sorts_and_deduplicates(self):
        assert caps.normalize_capabilities(["bus.read", "BUS.post", "bus.read"]) == [
            "bus.post",
            "bus.read",
        ]

    def test_wildcard_absorbs_everything_else(self):
        assert caps.normalize_capabilities(["bus.read", "*"]) == ["*"]

    def test_none_becomes_empty(self):
        assert caps.normalize_capabilities(None) == []

    def test_a_bare_string_is_not_a_capability_list(self):
        with pytest.raises(ValidationError):
            caps.normalize_capabilities("bus.read")

    @pytest.mark.parametrize("value", ["bus..read", "bus.*.read", "Bus/read", ""])
    def test_malformed_capabilities_are_rejected(self, value):
        with pytest.raises(ValidationError):
            caps.normalize_capability(value)

    def test_subtree_wildcard_is_allowed(self):
        assert caps.normalize_capability("bus.*") == "bus.*"


class TestCoverage:
    @pytest.mark.parametrize(
        "grant,capability,expected",
        [
            ("*", "anything.at.all", True),
            ("bus.post", "bus.post", True),
            ("bus.post", "bus.read", False),
            ("bus.*", "bus.post", True),
            ("bus.*", "bus", True),
            ("bus.*", "lock.acquire", False),
            ("bus.post", "bus.post.extra", False),
        ],
    )
    def test_grant_coverage(self, grant, capability, expected):
        assert caps.grant_covers(grant, capability) is expected

    def test_allows_scans_every_grant(self):
        granted = ["bus.read", "lock.*"]
        assert caps.allows(granted, "lock.acquire")
        assert not caps.allows(granted, "agent.mint")


class TestAttenuation:
    def test_a_subset_is_an_attenuation(self):
        assert caps.is_attenuation(["bus.read"], ["bus.read", "bus.post"])

    def test_escalation_is_not_an_attenuation(self):
        assert not caps.is_attenuation(["agent.mint"], ["bus.read"])

    def test_wildcard_parent_covers_any_child(self):
        assert caps.is_attenuation(["anything"], ["*"])

    def test_attenuate_returns_the_narrowed_set(self):
        assert caps.attenuate(["bus.read"], ["bus.read", "bus.post"]) == ["bus.read"]

    def test_attenuate_rejects_undelegatable_capabilities(self):
        with pytest.raises(ValidationError) as excinfo:
            caps.attenuate(["agent.mint", "bus.read"], ["bus.read"])
        assert "agent.mint" in str(excinfo.value)

    def test_wildcard_cannot_be_delegated_by_a_narrower_issuer(self):
        with pytest.raises(ValidationError):
            caps.attenuate(["*"], ["bus.read"])

    def test_root_can_delegate_the_wildcard(self):
        assert caps.attenuate(["*"], ["*"]) == ["*"]


class TestRoleDefaults:
    @pytest.mark.parametrize("role", sorted(caps.ROLE_CAPABILITIES))
    def test_every_role_default_is_a_valid_capability_set(self, role):
        defaults = caps.default_capabilities_for_role(role)
        assert defaults == caps.normalize_capabilities(defaults)

    def test_orchestrator_may_mint_but_a_worker_may_not(self):
        assert "agent.mint" in caps.default_capabilities_for_role("orchestrator")
        assert "agent.mint" not in caps.default_capabilities_for_role("worker")

    def test_unknown_roles_fall_back_to_a_minimal_set(self):
        assert caps.default_capabilities_for_role("archivist") == list(
            caps.DEFAULT_CAPABILITIES
        )

    def test_every_role_default_is_delegatable_by_a_root(self):
        for role in caps.ROLE_CAPABILITIES:
            caps.attenuate(
                caps.default_capabilities_for_role(role), caps.ROOT_CAPABILITIES
            )
