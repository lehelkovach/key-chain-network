"""CLI tests, driven through ``main()`` against a temporary database.

The CLI is the bootstrap and break-glass path: it has to work before a trust root
exists and without the HTTP service running, so these tests exercise it exactly
as an operator would, including the offline verification flow an agent uses when
it holds its own private key.
"""

import json

import pytest

import keychain_cli
from keychain import keys


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYCHAIN_MASTER_KEY", keys.generate_master_key())
    monkeypatch.setenv("KEYCHAIN_ROOT_NAME", "cli-root")
    monkeypatch.delenv("KEYCHAIN_AUTO_BOOTSTRAP_ROOT", raising=False)
    return str(tmp_path / "cli.db")


def run(capsys, db_path, *argv):
    """Invoke the CLI and return ``(exit_code, parsed_stdout)``."""
    code = keychain_cli.main(["--db", db_path, *argv])
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return code, payload


@pytest.fixture
def rooted(capsys, db_path):
    code, root = run(capsys, db_path, "init-root")
    assert code == 0
    return root


class TestBootstrap:
    def test_gen_master_key_prints_a_usable_key(self, capsys, db_path):
        code, payload = run(capsys, db_path, "gen-master-key")
        assert code == 0
        assert keys.key_wrapper_from_env(
            {"KEYCHAIN_MASTER_KEY": payload["KEYCHAIN_MASTER_KEY"]}
        ).seals

    def test_init_root_creates_a_default_root(self, rooted):
        assert rooted["name"] == "cli-root"
        assert rooted["is_default"] is True
        assert rooted["certificate"]["cert_type"] == "root"
        assert "d" not in rooted["public_key"]

    def test_init_root_twice_reports_a_conflict(self, capsys, db_path, rooted):
        code = keychain_cli.main(["--db", db_path, "init-root"])
        captured = capsys.readouterr()
        assert code == 2
        assert json.loads(captured.err)["conflict_code"] == "ROOT_EXISTS"

    def test_roots_lists_what_was_created(self, capsys, db_path, rooted):
        _code, payload = run(capsys, db_path, "roots")
        assert [root["name"] for root in payload["roots"]] == ["cli-root"]

    def test_jwks_exposes_the_root_key(self, capsys, db_path, rooted):
        _code, payload = run(capsys, db_path, "jwks")
        assert [key["kid"] for key in payload["keys"]] == [rooted["key_id"]]


class TestMinting:
    def test_mint_returns_an_identity_with_its_private_key(self, capsys, db_path,
                                                           rooted):
        code, payload = run(
            capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--role", "orchestrator",
        )
        assert code == 0
        assert payload["logical_handle"] == "agent:cursor.iac-bus.0"
        assert payload["private_key"]["d"]
        assert payload["certificate_chain"][-1]["cert_type"] == "root"

    def test_mint_writes_the_document_and_summarizes(self, capsys, db_path, rooted,
                                                    tmp_path):
        out = str(tmp_path / "identity.json")
        code, summary = run(
            capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--out", out,
        )
        assert code == 0
        assert summary["written_to"] == out
        assert summary["contains_private_key"] is True
        with open(out, "r", encoding="utf-8") as handle:
            assert json.load(handle)["logical_handle"] == "agent:cursor.iac-bus.0"

    def test_mint_allocates_a_child_under_a_parent_handle(self, capsys, db_path,
                                                          rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--role", "orchestrator", "--custody", "keychain")
        _code, child = run(
            capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--parent", "agent:cursor.iac-bus.0",
        )
        assert child["logical_handle"] == "agent:cursor.iac-bus.0-0"
        assert len(child["certificate_chain"]) == 3

    def test_mint_accepts_an_externally_generated_public_key(self, capsys, db_path,
                                                             rooted, tmp_path):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        key_path = str(tmp_path / "agent.jwk.json")
        with open(key_path, "w", encoding="utf-8") as handle:
            json.dump(jwk, handle)
        _code, payload = run(
            capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--public-key", key_path,
        )
        assert payload["key_id"] == jwk["kid"]
        assert "private_key" not in payload

    def test_mint_narrows_capabilities(self, capsys, db_path, rooted):
        _code, payload = run(
            capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--capabilities", "bus.read, bus.post",
        )
        assert payload["capabilities"] == ["bus.post", "bus.read"]

    def test_mint_without_a_root_reports_the_blocker(self, capsys, db_path):
        code = keychain_cli.main(
            ["--db", db_path, "mint", "--brand", "cursor", "--repo", "iac-bus"]
        )
        captured = capsys.readouterr()
        assert code == 2
        assert "no trust root configured" in json.loads(captured.err)["error"]


class TestInspection:
    def test_show_describes_an_agent(self, capsys, db_path, rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus")
        _code, payload = run(capsys, db_path, "show", "agent:cursor.iac-bus.0")
        assert payload["role"] == "worker"
        assert payload["certificate_chain"]

    def test_show_can_omit_the_chain(self, capsys, db_path, rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus")
        _code, payload = run(
            capsys, db_path, "show", "agent:cursor.iac-bus.0", "--no-chain"
        )
        assert "certificate_chain" not in payload

    def test_show_of_an_unknown_agent_fails(self, capsys, db_path, rooted):
        code = keychain_cli.main(["--db", db_path, "show", "agent:cursor.iac-bus.9"])
        capsys.readouterr()
        assert code == 2

    def test_list_and_filter(self, capsys, db_path, rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus")
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "repo-x")
        _code, everything = run(capsys, db_path, "list")
        assert len(everything["agents"]) == 2
        _code, filtered = run(capsys, db_path, "list", "--repo", "repo-x")
        assert len(filtered["agents"]) == 1

    def test_audit_records_the_mints(self, capsys, db_path, rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus")
        _code, payload = run(capsys, db_path, "audit")
        assert any(entry["event"] == "agent.mint" for entry in payload["audit"])
        assert any(entry["actor"] == "cli" for entry in payload["audit"])


class TestRevocation:
    def test_revoke_cascades_by_default(self, capsys, db_path, rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--role", "orchestrator", "--custody", "keychain")
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--parent", "agent:cursor.iac-bus.0")
        _code, payload = run(
            capsys, db_path, "revoke", "agent:cursor.iac-bus.0", "--reason", "leak"
        )
        assert len(payload["revoked"]) == 2

    def test_revoke_can_be_limited(self, capsys, db_path, rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--role", "orchestrator", "--custody", "keychain")
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--parent", "agent:cursor.iac-bus.0")
        _code, payload = run(
            capsys, db_path, "revoke", "agent:cursor.iac-bus.0", "--no-cascade"
        )
        assert payload["revoked"] == ["agent:cursor.iac-bus.0"]


class TestTokens:
    def test_token_from_the_store(self, capsys, db_path, rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--role", "orchestrator", "--custody", "keychain")
        _code, issued = run(
            capsys, db_path, "token", "agent:cursor.iac-bus.0", "--audience", "iac-bus"
        )
        code, verified = run(
            capsys, db_path, "verify-token", "--token", issued["token"],
            "--audience", "iac-bus",
        )
        assert code == 0
        assert verified["valid"] is True

    def test_an_agent_can_sign_its_own_token_offline(self, capsys, db_path, rooted,
                                                     tmp_path):
        """The end-to-end flow for an agent that never surrenders its key."""
        out = str(tmp_path / "identity.json")
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--role", "worker", "--out", out)
        _code, issued = run(
            capsys, db_path, "token", "--private-key", out, "--audience", "iac-bus"
        )
        assert issued["signed_locally"] is True
        assert issued["self_contained"] is True

        # A relying party checks it with nothing but the pinned root key id.
        code, verified = run(
            capsys, db_path, "verify-token", "--token", issued["token"],
            "--audience", "iac-bus", "--trusted-root-key-id", rooted["key_id"],
        )
        assert code == 0, verified
        assert verified["valid"] is True
        assert verified["claims"]["handle"] == "agent:cursor.iac-bus.0"

    def test_local_signing_requires_a_chain(self, capsys, db_path, rooted, tmp_path):
        key_path = str(tmp_path / "bare.jwk.json")
        with open(key_path, "w", encoding="utf-8") as handle:
            json.dump(keys.private_jwk(keys.generate_private_key()), handle)
        code = keychain_cli.main(
            ["--db", db_path, "token", "--private-key", key_path]
        )
        captured = capsys.readouterr()
        assert code == 2
        assert "certificate chain is required" in json.loads(captured.err)["error"]

    def test_verify_token_reports_failure_with_a_nonzero_exit(self, capsys, db_path,
                                                              rooted):
        code, payload = run(
            capsys, db_path, "verify-token", "--token", "not-a-token"
        )
        assert code == 1
        assert payload["valid"] is False

    def test_verify_token_enforces_required_capabilities(self, capsys, db_path,
                                                          rooted):
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--role", "worker", "--custody", "keychain")
        _code, issued = run(capsys, db_path, "token", "agent:cursor.iac-bus.0")
        code, payload = run(
            capsys, db_path, "verify-token", "--token", issued["token"],
            "--require-capabilities", "agent.mint",
        )
        assert code == 1
        assert any("missing required" in error for error in payload["errors"])


class TestChainVerification:
    def test_a_minted_chain_verifies_offline(self, capsys, db_path, rooted, tmp_path):
        out = str(tmp_path / "identity.json")
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--out", out)
        code, payload = run(
            capsys, db_path, "verify-chain", "--chain", out,
            "--trusted-root-key-id", rooted["key_id"],
        )
        assert code == 0
        assert payload["valid"] is True

    def test_an_untrusted_root_fails(self, capsys, db_path, rooted, tmp_path):
        out = str(tmp_path / "identity.json")
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--out", out)
        code, payload = run(
            capsys, db_path, "verify-chain", "--chain", out,
            "--trusted-root-key-id", "someone-else",
        )
        assert code == 1
        assert any("not trusted" in error for error in payload["errors"])

    def test_verification_against_the_local_store(self, capsys, db_path, rooted,
                                                  tmp_path):
        out = str(tmp_path / "identity.json")
        run(capsys, db_path, "mint", "--brand", "cursor", "--repo", "iac-bus",
            "--out", out)
        code, payload = run(capsys, db_path, "verify-chain", "--chain", out)
        assert code == 0
        assert payload["valid"] is True


class TestParser:
    def test_a_missing_command_is_rejected(self):
        with pytest.raises(SystemExit):
            keychain_cli.main([])

    def test_mint_requires_brand_and_repo(self):
        with pytest.raises(SystemExit):
            keychain_cli.main(["mint", "--brand", "cursor"])

    def test_an_invalid_custody_choice_is_rejected(self):
        with pytest.raises(SystemExit):
            keychain_cli.main(
                ["mint", "--brand", "cursor", "--repo", "x", "--custody", "vault"]
            )
