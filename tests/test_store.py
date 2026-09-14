"""Storage behaviour: uniqueness, hierarchy walks, endpoints, revocations."""

import datetime

import pytest

from keychain import keys
from keychain.canonical import to_iso8601, utcnow
from keychain.errors import ConflictError, NotFoundError
from keychain.store import (
    CUSTODY_AGENT,
    STATUS_ACTIVE,
    STATUS_REVOKED,
    SUBJECT_KIND_AGENT,
    KeyChainStore,
)


def add_root(store, name="root-a"):
    jwk = keys.public_jwk(keys.generate_private_key().public_key())
    certificate = {
        "cert_id": "cert-%s" % name,
        "cert_type": "root",
        "subject": {"root_id": "rid-%s" % name, "name": name, "key_id": jwk["kid"],
                    "public_key": jwk},
        "issuer": {"cert_id": None, "key_id": jwk["kid"], "self_signed": True,
                   "subject_ref": "root:%s" % name},
        "capabilities": ["*"],
        "issued_at": to_iso8601(utcnow()),
        "expires_at": None,
    }
    store.insert_certificate(certificate, root_key_id=jwk["kid"])
    return store.insert_root(
        name=name,
        key_id=jwk["kid"],
        public_jwk=jwk,
        sealed_private_key="kcw0.sealed",
        cert_id=certificate["cert_id"],
        capabilities=["*"],
        is_default=True,
        root_id="rid-%s" % name,
    )


def add_agent(store, root, handle, ordinal_path, parent=None, brand="cursor",
              repo_locale="iac-bus", role="worker"):
    jwk = keys.public_jwk(keys.generate_private_key().public_key())
    cert_id = "cert-%s" % handle
    store.insert_certificate(
        {
            "cert_id": cert_id,
            "cert_type": "agent",
            "subject": {"logical_handle": handle, "key_id": jwk["kid"],
                        "public_key": jwk},
            "issuer": {
                "cert_id": parent["cert_id"] if parent else root["cert_id"],
                "key_id": root["key_id"],
                "self_signed": False,
                "subject_ref": "root:%s" % root["name"],
            },
            "capabilities": ["bus.read"],
            "issued_at": to_iso8601(utcnow()),
            "expires_at": None,
        },
        root_key_id=root["key_id"],
    )
    return store.insert_agent(
        {
            "agent_uuid": "uuid-%s" % handle,
            "brand": brand,
            "repo_locale": repo_locale,
            "ordinal_path": ordinal_path,
            "logical_handle": handle,
            "parent_agent_uuid": parent["agent_uuid"] if parent else None,
            "role": role,
            "root_id": root["root_id"],
            "key_id": jwk["kid"],
            "public_jwk": jwk,
            "cert_id": cert_id,
            "capabilities": ["bus.read"],
        }
    )


@pytest.fixture
def seeded(store):
    root = add_root(store)
    master = add_agent(store, root, "agent:cursor.iac-bus.0", "0", role="orchestrator")
    child = add_agent(store, root, "agent:cursor.iac-bus.0-1", "0-1", parent=master)
    grandchild = add_agent(
        store, root, "agent:cursor.iac-bus.0-1-1", "0-1-1", parent=child
    )
    return {"root": root, "master": master, "child": child, "grandchild": grandchild}


class TestSchema:
    def test_a_fresh_store_is_empty(self, store):
        assert store.count_agents() == 0
        assert store.list_roots() == []
        assert store.count_revocations() == 0

    def test_schema_creation_is_idempotent(self, tmp_path):
        path = str(tmp_path / "keychain.db")
        with KeyChainStore(path) as first:
            add_root(first)
        with KeyChainStore(path) as second:
            assert len(second.list_roots()) == 1


class TestRoots:
    def test_insert_and_lookup_by_every_key(self, store):
        root = add_root(store)
        assert store.get_root(root["root_id"])["name"] == "root-a"
        assert store.get_root_by_name("root-a")["root_id"] == root["root_id"]
        assert store.get_root_by_key_id(root["key_id"])["root_id"] == root["root_id"]

    def test_duplicate_name_conflicts(self, store):
        add_root(store)
        with pytest.raises(ConflictError):
            add_root(store)

    def test_json_columns_round_trip(self, store):
        root = add_root(store)
        assert root["public_jwk"]["kty"] == "OKP"
        assert root["capabilities"] == ["*"]
        assert root["is_default"] is True

    def test_a_single_root_is_the_default_even_when_unflagged(self, store):
        jwk = keys.public_jwk(keys.generate_private_key().public_key())
        add_root(store, name="only")
        assert store.get_default_root()["name"] == "only"
        assert jwk["kty"] == "OKP"

    def test_set_default_root_moves_the_flag(self, store):
        first = add_root(store, name="first")
        second = add_root(store, name="second")
        store.set_default_root(second["root_id"])
        assert store.get_default_root()["root_id"] == second["root_id"]
        assert store.get_root(first["root_id"])["is_default"] is False

    def test_set_default_root_requires_an_existing_root(self, store):
        with pytest.raises(NotFoundError):
            store.set_default_root("missing")

    def test_no_default_when_several_roots_are_unflagged(self, store):
        add_root(store, name="first")
        second = add_root(store, name="second")
        store.set_default_root(second["root_id"])
        assert store.get_default_root() is not None


class TestAgents:
    def test_lookup_by_uuid_handle_and_key(self, seeded, store):
        master = seeded["master"]
        assert store.get_agent(master["agent_uuid"])["logical_handle"] == (
            master["logical_handle"]
        )
        assert store.get_agent_by_handle(master["logical_handle"])["agent_uuid"] == (
            master["agent_uuid"]
        )
        assert store.get_agent_by_key_id(master["key_id"])["agent_uuid"] == (
            master["agent_uuid"]
        )

    def test_missing_lookups_return_none(self, store):
        assert store.get_agent("nope") is None
        assert store.get_agent_by_handle("agent:cursor.iac-bus.0") is None

    def test_duplicate_handle_conflicts(self, seeded, store):
        with pytest.raises(ConflictError):
            add_agent(store, seeded["root"], "agent:cursor.iac-bus.0", "0")

    def test_defaults_are_applied(self, seeded):
        assert seeded["master"]["status"] == STATUS_ACTIVE
        assert seeded["master"]["custody"] == CUSTODY_AGENT
        assert seeded["master"]["sealed_private_key"] is None

    def test_filtered_listing(self, seeded, store):
        assert len(store.list_agents(brand="cursor")) == 3
        assert store.list_agents(brand="other") == []
        assert len(store.list_agents(role="orchestrator")) == 1
        assert len(store.list_agents(parent_agent_uuid=seeded["master"]["agent_uuid"])) == 1

    def test_listing_pagination(self, seeded, store):
        assert len(store.list_agents(limit=2)) == 2
        assert len(store.list_agents(limit=2, offset=2)) == 1

    def test_status_update(self, seeded, store):
        updated = store.update_agent_status(
            seeded["child"]["agent_uuid"], STATUS_REVOKED
        )
        assert updated["status"] == STATUS_REVOKED

    def test_unknown_status_is_rejected(self, seeded, store):
        with pytest.raises(ConflictError):
            store.update_agent_status(seeded["child"]["agent_uuid"], "sleepy")

    def test_status_update_requires_an_existing_agent(self, store):
        with pytest.raises(NotFoundError):
            store.update_agent_status("missing", STATUS_REVOKED)

    def test_forget_private_key(self, seeded, store):
        store._execute(
            "UPDATE agents SET sealed_private_key = 'kcw0.x', custody = 'keychain' "
            "WHERE agent_uuid = ?",
            (seeded["child"]["agent_uuid"],),
        )
        cleared = store.forget_agent_private_key(seeded["child"]["agent_uuid"])
        assert cleared["sealed_private_key"] is None
        assert cleared["custody"] == CUSTODY_AGENT


class TestHierarchy:
    def test_children_are_direct_only(self, seeded, store):
        children = store.list_children(seeded["master"]["agent_uuid"])
        assert [child["logical_handle"] for child in children] == [
            "agent:cursor.iac-bus.0-1"
        ]

    def test_descendants_are_transitive(self, seeded, store):
        descendants = store.list_descendants(seeded["master"]["agent_uuid"])
        assert {agent["logical_handle"] for agent in descendants} == {
            "agent:cursor.iac-bus.0-1",
            "agent:cursor.iac-bus.0-1-1",
        }

    def test_a_leaf_has_no_descendants(self, seeded, store):
        assert store.list_descendants(seeded["grandchild"]["agent_uuid"]) == []

    def test_next_child_ordinal_starts_at_zero(self, seeded, store):
        assert store.next_child_ordinal_index("cursor", "iac-bus", "0-1-1") == 0

    def test_next_child_ordinal_skips_used_indexes(self, seeded, store):
        assert store.next_child_ordinal_index("cursor", "iac-bus", "0") == 0
        add_agent(store, seeded["root"], "agent:cursor.iac-bus.0-0", "0-0",
                  parent=seeded["master"])
        assert store.next_child_ordinal_index("cursor", "iac-bus", "0") == 2

    def test_next_child_ordinal_is_namespace_scoped(self, seeded, store):
        assert store.next_child_ordinal_index("cursor", "repo-x", "0") == 0

    def test_next_child_ordinal_ignores_deeper_descendants(self, seeded, store):
        # "0-1-1" must not be counted as a child index of "0".
        assert store.next_child_ordinal_index("cursor", "iac-bus", "0") == 0


class TestEndpoints:
    def test_insert_then_update(self, seeded, store):
        agent_uuid = seeded["master"]["agent_uuid"]
        first, created = store.upsert_endpoint(
            agent_uuid, "web", "agent:cursor.iac-bus.0@web"
        )
        assert created is True
        second, created_again = store.upsert_endpoint(
            agent_uuid, "web", "agent:cursor.iac-bus.0@web"
        )
        assert created_again is False
        assert first["endpoint_uuid"] == second["endpoint_uuid"]

    def test_sessions_are_separate_endpoints(self, seeded, store):
        agent_uuid = seeded["master"]["agent_uuid"]
        store.upsert_endpoint(agent_uuid, "web", "agent:cursor.iac-bus.0@web")
        store.upsert_endpoint(
            agent_uuid, "web", "agent:cursor.iac-bus.0@web", session_id="s-2"
        )
        assert len(store.list_endpoints(agent_uuid)) == 2

    def test_the_same_endpoint_handle_may_repeat_across_sessions(self, seeded, store):
        agent_uuid = seeded["master"]["agent_uuid"]
        store.upsert_endpoint(
            agent_uuid, "web", "agent:cursor.iac-bus.0@web", session_id="a"
        )
        store.upsert_endpoint(
            agent_uuid, "web", "agent:cursor.iac-bus.0@web", session_id="b"
        )
        handles = {
            endpoint["endpoint_handle"] for endpoint in store.list_endpoints(agent_uuid)
        }
        assert handles == {"agent:cursor.iac-bus.0@web"}

    def test_touch_updates_last_seen(self, seeded, store):
        agent_uuid = seeded["master"]["agent_uuid"]
        store.upsert_endpoint(agent_uuid, "api", "agent:cursor.iac-bus.0@api")
        moment = utcnow() + datetime.timedelta(seconds=5)
        touched = store.touch_endpoint(agent_uuid, "api", seen_at=moment)
        assert touched["last_seen_at"] == to_iso8601(moment)

    def test_touch_requires_an_endpoint(self, seeded, store):
        with pytest.raises(NotFoundError):
            store.touch_endpoint(seeded["master"]["agent_uuid"], "slack")

    def test_deactivate_endpoints(self, seeded, store):
        agent_uuid = seeded["master"]["agent_uuid"]
        store.upsert_endpoint(agent_uuid, "api", "agent:cursor.iac-bus.0@api")
        store.deactivate_endpoints(agent_uuid)
        assert all(
            endpoint["is_active"] is False
            for endpoint in store.list_endpoints(agent_uuid)
        )

    def test_endpoints_are_deleted_with_their_agent(self, seeded, store):
        agent_uuid = seeded["grandchild"]["agent_uuid"]
        store.upsert_endpoint(agent_uuid, "api", "agent:cursor.iac-bus.0-1-1@api")
        store._execute("DELETE FROM agents WHERE agent_uuid = ?", (agent_uuid,))
        assert store.list_endpoints(agent_uuid) == []


class TestCertificates:
    def test_chain_walk_stops_at_the_root(self, seeded, store):
        chain = store.get_certificate_chain(seeded["child"]["cert_id"])
        assert [cert["cert_type"] for cert in chain][-1] == "root"

    def test_chain_walk_of_a_missing_cert_is_empty(self, store):
        assert store.get_certificate_chain("missing") == []

    def test_duplicate_cert_id_conflicts(self, seeded, store):
        certificate = store.get_certificate(seeded["child"]["cert_id"])
        with pytest.raises(ConflictError):
            store.insert_certificate(certificate, root_key_id=seeded["root"]["key_id"])

    def test_chain_walk_survives_a_cycle(self, seeded, store):
        # Defensive: a corrupted issuer link must not loop forever.
        store._execute(
            "UPDATE certificates SET issuer_cert_id = ? WHERE cert_id = ?",
            (seeded["child"]["cert_id"], seeded["root"]["cert_id"]),
        )
        store._execute(
            "UPDATE certificates SET document = replace(document, "
            "'\"self_signed\": true', '\"self_signed\": false') WHERE cert_id = ?",
            (seeded["root"]["cert_id"],),
        )
        assert len(store.get_certificate_chain(seeded["child"]["cert_id"])) <= 16


class TestRevocations:
    def test_insert_and_list(self, seeded, store):
        record = store.insert_revocation(
            SUBJECT_KIND_AGENT,
            seeded["child"]["logical_handle"],
            reason="compromised",
            agent_uuid=seeded["child"]["agent_uuid"],
            cert_id=seeded["child"]["cert_id"],
            key_id=seeded["child"]["key_id"],
        )
        assert record["reason"] == "compromised"
        assert store.count_revocations() == 1
        assert len(store.list_revocations()) == 1

    def test_revocation_is_idempotent(self, seeded, store):
        for _ in range(2):
            store.insert_revocation(
                SUBJECT_KIND_AGENT, seeded["child"]["logical_handle"]
            )
        assert store.count_revocations() == 1

    def test_revoked_sets_and_lookup(self, seeded, store):
        store.insert_revocation(
            SUBJECT_KIND_AGENT,
            seeded["child"]["logical_handle"],
            cert_id=seeded["child"]["cert_id"],
            key_id=seeded["child"]["key_id"],
        )
        assert seeded["child"]["key_id"] in store.revoked_key_ids()
        assert seeded["child"]["cert_id"] in store.revoked_cert_ids()
        assert store.is_key_revoked(seeded["child"]["key_id"]) is True
        assert store.is_key_revoked("other") is False
        assert store.is_key_revoked(None) is False

    def test_since_filter(self, seeded, store):
        store.insert_revocation(
            SUBJECT_KIND_AGENT, seeded["child"]["logical_handle"],
            revoked_at=utcnow() - datetime.timedelta(days=2),
        )
        assert store.list_revocations(since=to_iso8601(utcnow())) == []


class TestAudit:
    def test_append_and_read_back_newest_first(self, store):
        store.append_audit("agent.mint", "created", logical_handle="agent:a.b.0")
        store.append_audit("agent.revoke", "revoked", logical_handle="agent:a.b.0")
        entries = store.list_audit()
        assert [entry["event"] for entry in entries] == [
            "agent.revoke",
            "agent.mint",
        ]

    def test_detail_is_json(self, store):
        store.append_audit("agent.mint", "created", detail={"medium": "web"})
        assert store.list_audit()[0]["detail"] == {"medium": "web"}

    def test_filter_by_handle(self, store):
        store.append_audit("agent.mint", "created", logical_handle="agent:a.b.0")
        store.append_audit("agent.mint", "created", logical_handle="agent:a.b.1")
        assert len(store.list_audit(logical_handle="agent:a.b.0")) == 1
