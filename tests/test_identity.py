"""Grammar tests for the ACP v2 identity model."""

import pytest

from keychain import identity
from keychain.errors import ValidationError


class TestNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [("  Cursor ", "cursor"), ("CURSOR", "cursor"), ("open-claw", "open-claw")],
    )
    def test_brand_is_trimmed_and_lowercased(self, raw, expected):
        assert identity.normalize_brand(raw) == expected

    @pytest.mark.parametrize("raw", ["", "   ", "cursor!", "cur sor", "cursor.ide"])
    def test_brand_rejects_invalid_values(self, raw):
        with pytest.raises(ValidationError):
            identity.normalize_brand(raw)

    def test_repo_locale_allows_dots(self):
        assert identity.normalize_repo_locale("Repo.X") == "repo.x"

    @pytest.mark.parametrize("raw", [".repo", "repo.", "repo/x", ""])
    def test_repo_locale_rejects_invalid_values(self, raw):
        with pytest.raises(ValidationError):
            identity.normalize_repo_locale(raw)

    @pytest.mark.parametrize("medium", identity.MEDIA)
    def test_all_acp_media_are_accepted(self, medium):
        assert identity.normalize_medium(medium.upper()) == medium

    def test_unknown_medium_is_rejected(self):
        with pytest.raises(ValidationError):
            identity.normalize_medium("carrier-pigeon")

    def test_blank_session_id_becomes_none(self):
        assert identity.normalize_session_id("   ") is None
        assert identity.normalize_session_id(None) is None

    def test_session_id_rejects_unsafe_characters(self):
        with pytest.raises(ValidationError):
            identity.normalize_session_id("session id/../etc")


class TestOrdinalPaths:
    @pytest.mark.parametrize("path", ["0", "0-1", "0-4-8", "12", "1-2-3-4"])
    def test_valid_paths_round_trip(self, path):
        assert identity.validate_ordinal_path(path) == path
        assert identity.format_ordinal_path(identity.parse_ordinal_path(path)) == path

    @pytest.mark.parametrize("path", ["", "-1", "0-", "0--1", "a", "0.1", "0-x"])
    def test_invalid_paths_are_rejected(self, path):
        with pytest.raises(ValidationError):
            identity.validate_ordinal_path(path)

    def test_leading_zeros_are_rejected(self):
        # "01" and "1" would be distinct handles for the same logical position.
        with pytest.raises(ValidationError):
            identity.validate_ordinal_path("0-01")

    def test_depth_is_bounded(self):
        too_deep = "-".join(["1"] * (identity.MAX_ORDINAL_DEPTH + 1))
        with pytest.raises(ValidationError):
            identity.validate_ordinal_path(too_deep)

    def test_master_has_no_parent(self):
        assert identity.parent_ordinal_path("0") is None
        assert identity.parent_ordinal_path("0-4-8") == "0-4"

    def test_child_ordinal_path(self):
        assert identity.child_ordinal_path("0", 1) == "0-1"
        assert identity.child_ordinal_path("0-4", 8) == "0-4-8"

    def test_child_index_must_be_a_non_negative_integer(self):
        with pytest.raises(ValidationError):
            identity.child_ordinal_path("0", -1)
        with pytest.raises(ValidationError):
            identity.child_ordinal_path("0", "1")

    @pytest.mark.parametrize(
        "parent,child,expected",
        [
            ("0", "0-1", True),
            ("0", "0-1-2", False),
            ("0", "1-1", False),
            ("0-4", "0-4-8", True),
            ("0", "0", False),
        ],
    )
    def test_direct_child_detection(self, parent, child, expected):
        assert identity.is_direct_child_ordinal(parent, child) is expected

    @pytest.mark.parametrize(
        "ancestor,candidate,expected",
        [("0", "0-1-2", True), ("0-1", "0-2-1", False), ("0", "0", False)],
    )
    def test_descendant_detection(self, ancestor, candidate, expected):
        assert identity.is_descendant_ordinal(ancestor, candidate) is expected


class TestHandles:
    def test_logical_handle_matches_the_acp_v2_regex(self):
        handle = identity.build_logical_handle("Cursor", "IAC-Bus", "0-1")
        assert handle == "agent:cursor.iac-bus.0-1"
        assert identity.LOGICAL_HANDLE_RE.match(handle)

    def test_endpoint_handle_appends_medium(self):
        handle = identity.build_endpoint_handle("agent:cursor.iac-bus.0", "web")
        assert handle == "agent:cursor.iac-bus.0@web"

    @pytest.mark.parametrize(
        "handle,expected",
        [
            ("agent:cursor.iac-bus.0", ("cursor", "iac-bus", "0")),
            ("agent:cursor.repo-x.0-1", ("cursor", "repo-x", "0-1")),
            # repo_locale may contain dots; the ordinal is taken from the last one.
            ("agent:cursor.repo.x.y.0-4-8", ("cursor", "repo.x.y", "0-4-8")),
        ],
    )
    def test_parse_logical_handle(self, handle, expected):
        assert identity.parse_logical_handle(handle) == expected

    @pytest.mark.parametrize(
        "handle",
        [
            "cursor.iac-bus.0",
            "agent:cursor.0",
            "agent:cursor.iac-bus.",
            "agent:cursor.iac-bus.x",
            "agent:Cursor.iac-bus.0",
            "",
        ],
    )
    def test_invalid_logical_handles_are_rejected(self, handle):
        with pytest.raises(ValidationError):
            identity.validate_logical_handle(handle)

    def test_parse_endpoint_handle(self):
        assert identity.parse_endpoint_handle("agent:cursor.iac-bus.0@slack") == (
            "agent:cursor.iac-bus.0",
            "slack",
        )

    def test_endpoint_handle_requires_a_medium(self):
        with pytest.raises(ValidationError):
            identity.parse_endpoint_handle("agent:cursor.iac-bus.0")

    def test_same_namespace(self):
        assert identity.same_namespace(
            "agent:cursor.iac-bus.0", "agent:cursor.iac-bus.0-1"
        )
        assert not identity.same_namespace(
            "agent:cursor.iac-bus.0", "agent:cursor.repo-x.0"
        )


class TestUuidMinting:
    def test_random_mode_yields_distinct_uuids(self):
        first = identity.mint_agent_uuid("agent:cursor.iac-bus.0")
        second = identity.mint_agent_uuid("agent:cursor.iac-bus.0")
        assert first != second
        assert identity.validate_agent_uuid(first) == first

    def test_derived_mode_is_reproducible(self):
        args = ("agent:cursor.iac-bus.0",)
        kwargs = {"mode": identity.UUID_MODE_DERIVED, "namespace_seed": "root-key"}
        assert identity.mint_agent_uuid(*args, **kwargs) == identity.mint_agent_uuid(
            *args, **kwargs
        )

    def test_derived_mode_separates_trust_roots(self):
        first = identity.mint_agent_uuid(
            "agent:cursor.iac-bus.0",
            mode=identity.UUID_MODE_DERIVED,
            namespace_seed="root-a",
        )
        second = identity.mint_agent_uuid(
            "agent:cursor.iac-bus.0",
            mode=identity.UUID_MODE_DERIVED,
            namespace_seed="root-b",
        )
        assert first != second

    def test_derived_mode_requires_a_seed(self):
        with pytest.raises(ValidationError):
            identity.mint_agent_uuid(
                "agent:cursor.iac-bus.0", mode=identity.UUID_MODE_DERIVED
            )

    def test_unknown_mode_is_rejected(self):
        with pytest.raises(ValidationError):
            identity.mint_agent_uuid("agent:cursor.iac-bus.0", mode="sequential")

    def test_agent_uuid_must_be_a_uuid(self):
        with pytest.raises(ValidationError):
            identity.validate_agent_uuid("not-a-uuid")
