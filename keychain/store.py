"""SQLite-backed storage for trust roots, agents, certificates and revocations.

SQLite is the default because a KeyChain instance is a low-write, high-read
authority: minting happens once per agent, while resolution and verification are
mostly offline against the certificate the agent already holds. The schema
mirrors the ACP v2 draft in ``iac-bus/docs/sql/ACP_V2_SCHEMA.sql`` so identities
minted here drop straight into a bus deployment, and
``docs/sql/KEYCHAIN_SCHEMA.sql`` carries the equivalent Postgres DDL for when a
deployment outgrows a single file.

One deliberate deviation from the ACP v2 draft: ``agent_endpoints.endpoint_handle``
is indexed but not unique. The draft marks it unique while also keying endpoints
on ``(agent_uuid, medium, session_id)``, which cannot both hold once one agent has
two sessions on the same medium -- both would derive the same
``<logical-handle>@<medium>``.
"""

import json
import sqlite3
import threading
import uuid

from .canonical import to_iso8601, utcnow
from .errors import ConflictError, NotFoundError

MEMORY_PATH = ":memory:"

SUBJECT_KIND_AGENT = "agent"
SUBJECT_KIND_ROOT = "root"
SUBJECT_KIND_CERTIFICATE = "certificate"

STATUS_ACTIVE = "active"
STATUS_IDLE = "idle"
STATUS_BLOCKED = "blocked"
STATUS_REVOKED = "revoked"
STATUS_TERMINATED = "terminated"
AGENT_STATUSES = (
    STATUS_ACTIVE,
    STATUS_IDLE,
    STATUS_BLOCKED,
    STATUS_REVOKED,
    STATUS_TERMINATED,
)

CUSTODY_AGENT = "agent"
CUSTODY_KEYCHAIN = "keychain"
CUSTODY_MODES = (CUSTODY_AGENT, CUSTODY_KEYCHAIN)

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_roots (
    root_id            TEXT PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,
    key_id             TEXT NOT NULL UNIQUE,
    public_jwk         TEXT NOT NULL,
    sealed_private_key TEXT,
    cert_id            TEXT NOT NULL,
    capabilities       TEXT NOT NULL DEFAULT '["*"]',
    is_default         INTEGER NOT NULL DEFAULT 0,
    metadata           TEXT NOT NULL DEFAULT '{}',
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    cert_id        TEXT PRIMARY KEY,
    cert_type      TEXT NOT NULL,
    subject_ref    TEXT NOT NULL,
    subject_key_id TEXT NOT NULL,
    issuer_cert_id TEXT,
    issuer_key_id  TEXT NOT NULL,
    root_key_id    TEXT NOT NULL,
    document       TEXT NOT NULL,
    issued_at      TEXT NOT NULL,
    expires_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_certificates_subject
    ON certificates(subject_ref);
CREATE INDEX IF NOT EXISTS idx_certificates_subject_key
    ON certificates(subject_key_id);
CREATE INDEX IF NOT EXISTS idx_certificates_issuer
    ON certificates(issuer_cert_id);

CREATE TABLE IF NOT EXISTS agents (
    agent_uuid         TEXT PRIMARY KEY,
    brand              TEXT NOT NULL,
    repo_locale        TEXT NOT NULL,
    ordinal_path       TEXT NOT NULL,
    logical_handle     TEXT NOT NULL UNIQUE,
    parent_agent_uuid  TEXT REFERENCES agents(agent_uuid) ON DELETE SET NULL,
    role               TEXT NOT NULL DEFAULT 'worker',
    status             TEXT NOT NULL DEFAULT 'active',
    root_id            TEXT NOT NULL REFERENCES trust_roots(root_id),
    key_id             TEXT NOT NULL UNIQUE,
    public_jwk         TEXT NOT NULL,
    sealed_private_key TEXT,
    custody            TEXT NOT NULL DEFAULT 'agent',
    cert_id            TEXT NOT NULL REFERENCES certificates(cert_id),
    capabilities       TEXT NOT NULL DEFAULT '[]',
    metadata           TEXT NOT NULL DEFAULT '{}',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agents_parent ON agents(parent_agent_uuid);
CREATE INDEX IF NOT EXISTS idx_agents_namespace
    ON agents(brand, repo_locale, ordinal_path);
CREATE INDEX IF NOT EXISTS idx_agents_root ON agents(root_id);

CREATE TABLE IF NOT EXISTS agent_endpoints (
    endpoint_uuid   TEXT PRIMARY KEY,
    agent_uuid      TEXT NOT NULL REFERENCES agents(agent_uuid) ON DELETE CASCADE,
    medium          TEXT NOT NULL,
    endpoint_handle TEXT NOT NULL,
    session_id      TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1,
    last_seen_at    TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (agent_uuid, medium, session_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_endpoints_agent
    ON agent_endpoints(agent_uuid);
CREATE INDEX IF NOT EXISTS idx_agent_endpoints_handle
    ON agent_endpoints(endpoint_handle);

CREATE TABLE IF NOT EXISTS revocations (
    revocation_id TEXT PRIMARY KEY,
    subject_kind  TEXT NOT NULL,
    subject_ref   TEXT NOT NULL,
    agent_uuid    TEXT,
    cert_id       TEXT,
    key_id        TEXT,
    reason        TEXT,
    revoked_at    TEXT NOT NULL,
    UNIQUE (subject_kind, subject_ref)
);

CREATE INDEX IF NOT EXISTS idx_revocations_key ON revocations(key_id);
CREATE INDEX IF NOT EXISTS idx_revocations_cert ON revocations(cert_id);

CREATE TABLE IF NOT EXISTS mint_audit (
    audit_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    event          TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    agent_uuid     TEXT,
    logical_handle TEXT,
    actor          TEXT,
    detail         TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mint_audit_handle ON mint_audit(logical_handle);
CREATE INDEX IF NOT EXISTS idx_mint_audit_created ON mint_audit(created_at);
"""

SCHEMA_VERSION = "1"


def _loads(value, fallback):
    if value is None:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


class KeyChainStore:
    """Thread-safe SQLite store.

    Flask serves requests from a thread pool, so every statement runs under a
    single re-entrant lock. Minting is write-light, and holding one lock is far
    easier to reason about than per-connection state when the same process also
    needs read-modify-write sequences such as allocating the next child ordinal.
    """

    def __init__(self, path=MEMORY_PATH):
        self.path = path
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            if path != MEMORY_PATH:
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.executescript(SCHEMA)
            self._connection.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('version', ?)",
                (SCHEMA_VERSION,),
            )
            self._connection.commit()

    def close(self):
        with self._lock:
            self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc_info):
        self.close()

    # -- low level -----------------------------------------------------------

    def _execute(self, sql, params=()):
        with self._lock:
            cursor = self._connection.execute(sql, params)
            self._connection.commit()
            return cursor

    def _query_one(self, sql, params=()):
        with self._lock:
            row = self._connection.execute(sql, params).fetchone()
        return dict(row) if row is not None else None

    def _query_all(self, sql, params=()):
        with self._lock:
            rows = self._connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    # -- trust roots ---------------------------------------------------------

    def insert_root(
        self,
        name,
        key_id,
        public_jwk,
        sealed_private_key,
        cert_id,
        capabilities,
        is_default=False,
        metadata=None,
        root_id=None,
        created_at=None,
    ):
        record = {
            "root_id": root_id or str(uuid.uuid4()),
            "name": name,
            "key_id": key_id,
            "public_jwk": json.dumps(public_jwk, sort_keys=True),
            "sealed_private_key": sealed_private_key,
            "cert_id": cert_id,
            "capabilities": json.dumps(list(capabilities), sort_keys=True),
            "is_default": 1 if is_default else 0,
            "metadata": json.dumps(metadata or {}, sort_keys=True),
            "created_at": to_iso8601(created_at or utcnow()),
        }
        try:
            self._execute(
                """
                INSERT INTO trust_roots(
                    root_id, name, key_id, public_jwk, sealed_private_key, cert_id,
                    capabilities, is_default, metadata, created_at
                ) VALUES(
                    :root_id, :name, :key_id, :public_jwk, :sealed_private_key,
                    :cert_id, :capabilities, :is_default, :metadata, :created_at
                )
                """,
                record,
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "trust root already exists: %s" % exc, conflict_code="ROOT_EXISTS"
            ) from exc
        return self.get_root(record["root_id"])

    def _hydrate_root(self, row):
        if row is None:
            return None
        row["public_jwk"] = _loads(row["public_jwk"], {})
        row["capabilities"] = _loads(row["capabilities"], [])
        row["metadata"] = _loads(row["metadata"], {})
        row["is_default"] = bool(row["is_default"])
        return row

    def get_root(self, root_id):
        return self._hydrate_root(
            self._query_one("SELECT * FROM trust_roots WHERE root_id = ?", (root_id,))
        )

    def get_root_by_name(self, name):
        return self._hydrate_root(
            self._query_one("SELECT * FROM trust_roots WHERE name = ?", (name,))
        )

    def get_root_by_key_id(self, key_id):
        return self._hydrate_root(
            self._query_one("SELECT * FROM trust_roots WHERE key_id = ?", (key_id,))
        )

    def list_roots(self):
        return [
            self._hydrate_root(row)
            for row in self._query_all(
                "SELECT * FROM trust_roots ORDER BY is_default DESC, created_at ASC"
            )
        ]

    def get_default_root(self):
        root = self._hydrate_root(
            self._query_one(
                "SELECT * FROM trust_roots WHERE is_default = 1 "
                "ORDER BY created_at ASC LIMIT 1"
            )
        )
        if root is not None:
            return root
        roots = self.list_roots()
        return roots[0] if len(roots) == 1 else None

    def set_default_root(self, root_id):
        with self._lock:
            self._connection.execute("UPDATE trust_roots SET is_default = 0")
            cursor = self._connection.execute(
                "UPDATE trust_roots SET is_default = 1 WHERE root_id = ?", (root_id,)
            )
            self._connection.commit()
        if cursor.rowcount == 0:
            raise NotFoundError("trust root not found: %s" % root_id)
        return self.get_root(root_id)

    # -- certificates --------------------------------------------------------

    def insert_certificate(self, certificate, root_key_id):
        subject = certificate.get("subject") or {}
        issuer = certificate.get("issuer") or {}
        if certificate.get("cert_type") == "root":
            subject_ref = "root:%s" % subject.get("root_id")
        else:
            subject_ref = subject.get("logical_handle")
        record = {
            "cert_id": certificate["cert_id"],
            "cert_type": certificate["cert_type"],
            "subject_ref": subject_ref,
            "subject_key_id": subject.get("key_id"),
            "issuer_cert_id": issuer.get("cert_id"),
            "issuer_key_id": issuer.get("key_id"),
            "root_key_id": root_key_id,
            "document": json.dumps(certificate, sort_keys=True),
            "issued_at": certificate.get("issued_at"),
            "expires_at": certificate.get("expires_at"),
        }
        try:
            self._execute(
                """
                INSERT INTO certificates(
                    cert_id, cert_type, subject_ref, subject_key_id, issuer_cert_id,
                    issuer_key_id, root_key_id, document, issued_at, expires_at
                ) VALUES(
                    :cert_id, :cert_type, :subject_ref, :subject_key_id,
                    :issuer_cert_id, :issuer_key_id, :root_key_id, :document,
                    :issued_at, :expires_at
                )
                """,
                record,
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "certificate already exists: %s" % certificate["cert_id"],
                conflict_code="CERT_EXISTS",
            ) from exc
        return certificate

    def get_certificate(self, cert_id):
        row = self._query_one(
            "SELECT * FROM certificates WHERE cert_id = ?", (cert_id,)
        )
        if row is None:
            return None
        return _loads(row["document"], None)

    def get_certificate_chain(self, cert_id, max_depth=16):
        """Walk ``issuer_cert_id`` links from a leaf up to its self-signed root."""
        chain = []
        seen = set()
        current = cert_id
        while current and len(chain) < max_depth:
            if current in seen:
                break
            seen.add(current)
            certificate = self.get_certificate(current)
            if certificate is None:
                break
            chain.append(certificate)
            issuer = certificate.get("issuer") or {}
            if issuer.get("self_signed"):
                break
            current = issuer.get("cert_id")
        return chain

    # -- agents --------------------------------------------------------------

    def insert_agent(self, record):
        row = dict(record)
        row["capabilities"] = json.dumps(
            list(row.get("capabilities") or []), sort_keys=True
        )
        row["public_jwk"] = json.dumps(row.get("public_jwk") or {}, sort_keys=True)
        row["metadata"] = json.dumps(row.get("metadata") or {}, sort_keys=True)
        row.setdefault("status", STATUS_ACTIVE)
        row.setdefault("custody", CUSTODY_AGENT)
        row.setdefault("sealed_private_key", None)
        row.setdefault("parent_agent_uuid", None)
        now = to_iso8601(utcnow())
        row.setdefault("created_at", now)
        row.setdefault("updated_at", now)
        try:
            self._execute(
                """
                INSERT INTO agents(
                    agent_uuid, brand, repo_locale, ordinal_path, logical_handle,
                    parent_agent_uuid, role, status, root_id, key_id, public_jwk,
                    sealed_private_key, custody, cert_id, capabilities, metadata,
                    created_at, updated_at
                ) VALUES(
                    :agent_uuid, :brand, :repo_locale, :ordinal_path, :logical_handle,
                    :parent_agent_uuid, :role, :status, :root_id, :key_id, :public_jwk,
                    :sealed_private_key, :custody, :cert_id, :capabilities, :metadata,
                    :created_at, :updated_at
                )
                """,
                row,
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "agent already exists: %s" % exc, conflict_code="AGENT_EXISTS"
            ) from exc
        return self.get_agent(row["agent_uuid"])

    def _hydrate_agent(self, row):
        if row is None:
            return None
        row["public_jwk"] = _loads(row["public_jwk"], {})
        row["capabilities"] = _loads(row["capabilities"], [])
        row["metadata"] = _loads(row["metadata"], {})
        return row

    def get_agent(self, agent_uuid):
        return self._hydrate_agent(
            self._query_one("SELECT * FROM agents WHERE agent_uuid = ?", (agent_uuid,))
        )

    def get_agent_by_handle(self, logical_handle):
        return self._hydrate_agent(
            self._query_one(
                "SELECT * FROM agents WHERE logical_handle = ?", (logical_handle,)
            )
        )

    def get_agent_by_key_id(self, key_id):
        return self._hydrate_agent(
            self._query_one("SELECT * FROM agents WHERE key_id = ?", (key_id,))
        )

    def list_agents(self, brand=None, repo_locale=None, role=None, status=None,
                    parent_agent_uuid=None, limit=100, offset=0):
        clauses = []
        params = []
        for column, value in (
            ("brand", brand),
            ("repo_locale", repo_locale),
            ("role", role),
            ("status", status),
            ("parent_agent_uuid", parent_agent_uuid),
        ):
            if value is not None:
                clauses.append("%s = ?" % column)
                params.append(value)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.extend([int(limit), int(offset)])
        return [
            self._hydrate_agent(row)
            for row in self._query_all(
                "SELECT * FROM agents %s ORDER BY created_at ASC, logical_handle ASC "
                "LIMIT ? OFFSET ?" % where,
                tuple(params),
            )
        ]

    def count_agents(self):
        row = self._query_one("SELECT COUNT(*) AS total FROM agents")
        return int(row["total"]) if row else 0

    def update_agent_status(self, agent_uuid, status):
        if status not in AGENT_STATUSES:
            raise ConflictError(
                "unknown agent status %r" % status, conflict_code="INVALID_STATUS"
            )
        cursor = self._execute(
            "UPDATE agents SET status = ?, updated_at = ? WHERE agent_uuid = ?",
            (status, to_iso8601(utcnow()), agent_uuid),
        )
        if cursor.rowcount == 0:
            raise NotFoundError("agent not found: %s" % agent_uuid)
        return self.get_agent(agent_uuid)

    def forget_agent_private_key(self, agent_uuid):
        """Drop a stored private key without touching the identity itself."""
        self._execute(
            "UPDATE agents SET sealed_private_key = NULL, custody = ?, "
            "updated_at = ? WHERE agent_uuid = ?",
            (CUSTODY_AGENT, to_iso8601(utcnow()), agent_uuid),
        )
        return self.get_agent(agent_uuid)

    def list_children(self, agent_uuid):
        return [
            self._hydrate_agent(row)
            for row in self._query_all(
                "SELECT * FROM agents WHERE parent_agent_uuid = ? "
                "ORDER BY ordinal_path ASC",
                (agent_uuid,),
            )
        ]

    def list_descendants(self, agent_uuid):
        """Breadth-first descendants, used to cascade a revocation."""
        descendants = []
        frontier = [agent_uuid]
        seen = {agent_uuid}
        while frontier:
            current = frontier.pop(0)
            for child in self.list_children(current):
                if child["agent_uuid"] in seen:
                    continue
                seen.add(child["agent_uuid"])
                descendants.append(child)
                frontier.append(child["agent_uuid"])
        return descendants

    def next_child_ordinal_index(self, brand, repo_locale, parent_ordinal_path):
        """Lowest unused child index under ``parent_ordinal_path``.

        Reuses gaps left by revoked siblings only if their rows were deleted;
        existing rows always hold their index so a handle is never recycled while
        the identity that owned it is still on record.
        """
        prefix = "%s-" % parent_ordinal_path
        rows = self._query_all(
            "SELECT ordinal_path FROM agents "
            "WHERE brand = ? AND repo_locale = ? AND ordinal_path LIKE ?",
            (brand, repo_locale, prefix + "%"),
        )
        used = set()
        for row in rows:
            tail = row["ordinal_path"][len(prefix) :]
            if tail.isdigit():
                used.add(int(tail))
        index = 0
        while index in used:
            index += 1
        return index

    # -- endpoints -----------------------------------------------------------

    def upsert_endpoint(self, agent_uuid, medium, endpoint_handle, session_id=None,
                        metadata=None, last_seen_at=None):
        now = to_iso8601(utcnow())
        existing = self.get_endpoint(agent_uuid, medium, session_id)
        if existing is not None:
            self._execute(
                "UPDATE agent_endpoints SET endpoint_handle = ?, is_active = 1, "
                "last_seen_at = ?, metadata = ?, updated_at = ? "
                "WHERE endpoint_uuid = ?",
                (
                    endpoint_handle,
                    to_iso8601(last_seen_at) if last_seen_at else existing["last_seen_at"],
                    json.dumps(metadata or existing["metadata"] or {}, sort_keys=True),
                    now,
                    existing["endpoint_uuid"],
                ),
            )
            return self.get_endpoint(agent_uuid, medium, session_id), False
        record = {
            "endpoint_uuid": str(uuid.uuid4()),
            "agent_uuid": agent_uuid,
            "medium": medium,
            "endpoint_handle": endpoint_handle,
            "session_id": session_id,
            "last_seen_at": to_iso8601(last_seen_at) if last_seen_at else None,
            "metadata": json.dumps(metadata or {}, sort_keys=True),
            "created_at": now,
            "updated_at": now,
        }
        self._execute(
            """
            INSERT INTO agent_endpoints(
                endpoint_uuid, agent_uuid, medium, endpoint_handle, session_id,
                is_active, last_seen_at, metadata, created_at, updated_at
            ) VALUES(
                :endpoint_uuid, :agent_uuid, :medium, :endpoint_handle, :session_id,
                1, :last_seen_at, :metadata, :created_at, :updated_at
            )
            """,
            record,
        )
        return self.get_endpoint(agent_uuid, medium, session_id), True

    def _hydrate_endpoint(self, row):
        if row is None:
            return None
        row["metadata"] = _loads(row["metadata"], {})
        row["is_active"] = bool(row["is_active"])
        return row

    def get_endpoint(self, agent_uuid, medium, session_id=None):
        if session_id is None:
            sql = (
                "SELECT * FROM agent_endpoints WHERE agent_uuid = ? AND medium = ? "
                "AND session_id IS NULL"
            )
            params = (agent_uuid, medium)
        else:
            sql = (
                "SELECT * FROM agent_endpoints WHERE agent_uuid = ? AND medium = ? "
                "AND session_id = ?"
            )
            params = (agent_uuid, medium, session_id)
        return self._hydrate_endpoint(self._query_one(sql, params))

    def list_endpoints(self, agent_uuid):
        return [
            self._hydrate_endpoint(row)
            for row in self._query_all(
                "SELECT * FROM agent_endpoints WHERE agent_uuid = ? "
                "ORDER BY created_at ASC",
                (agent_uuid,),
            )
        ]

    def touch_endpoint(self, agent_uuid, medium, session_id=None, seen_at=None):
        endpoint = self.get_endpoint(agent_uuid, medium, session_id)
        if endpoint is None:
            raise NotFoundError(
                "endpoint not found for agent %s on medium %s" % (agent_uuid, medium)
            )
        timestamp = to_iso8601(seen_at or utcnow())
        self._execute(
            "UPDATE agent_endpoints SET last_seen_at = ?, is_active = 1, "
            "updated_at = ? WHERE endpoint_uuid = ?",
            (timestamp, timestamp, endpoint["endpoint_uuid"]),
        )
        return self.get_endpoint(agent_uuid, medium, session_id)

    def deactivate_endpoints(self, agent_uuid):
        self._execute(
            "UPDATE agent_endpoints SET is_active = 0, updated_at = ? "
            "WHERE agent_uuid = ?",
            (to_iso8601(utcnow()), agent_uuid),
        )

    # -- revocations ---------------------------------------------------------

    def insert_revocation(self, subject_kind, subject_ref, reason=None,
                          agent_uuid=None, cert_id=None, key_id=None,
                          revoked_at=None):
        record = {
            "revocation_id": str(uuid.uuid4()),
            "subject_kind": subject_kind,
            "subject_ref": subject_ref,
            "agent_uuid": agent_uuid,
            "cert_id": cert_id,
            "key_id": key_id,
            "reason": reason,
            "revoked_at": to_iso8601(revoked_at or utcnow()),
        }
        try:
            self._execute(
                """
                INSERT INTO revocations(
                    revocation_id, subject_kind, subject_ref, agent_uuid, cert_id,
                    key_id, reason, revoked_at
                ) VALUES(
                    :revocation_id, :subject_kind, :subject_ref, :agent_uuid,
                    :cert_id, :key_id, :reason, :revoked_at
                )
                """,
                record,
            )
        except sqlite3.IntegrityError:
            return self._query_one(
                "SELECT * FROM revocations WHERE subject_kind = ? AND subject_ref = ?",
                (subject_kind, subject_ref),
            )
        return self._query_one(
            "SELECT * FROM revocations WHERE revocation_id = ?",
            (record["revocation_id"],),
        )

    def list_revocations(self, since=None, limit=500):
        if since:
            return self._query_all(
                "SELECT * FROM revocations WHERE revoked_at >= ? "
                "ORDER BY revoked_at ASC LIMIT ?",
                (since, int(limit)),
            )
        return self._query_all(
            "SELECT * FROM revocations ORDER BY revoked_at ASC LIMIT ?", (int(limit),)
        )

    def revoked_key_ids(self):
        return {
            row["key_id"]
            for row in self._query_all(
                "SELECT key_id FROM revocations WHERE key_id IS NOT NULL"
            )
        }

    def revoked_cert_ids(self):
        return {
            row["cert_id"]
            for row in self._query_all(
                "SELECT cert_id FROM revocations WHERE cert_id IS NOT NULL"
            )
        }

    def is_key_revoked(self, key_id):
        if key_id is None:
            return False
        return (
            self._query_one(
                "SELECT 1 AS hit FROM revocations WHERE key_id = ? LIMIT 1", (key_id,)
            )
            is not None
        )

    def count_revocations(self):
        row = self._query_one("SELECT COUNT(*) AS total FROM revocations")
        return int(row["total"]) if row else 0

    # -- audit ---------------------------------------------------------------

    def append_audit(self, event, outcome, agent_uuid=None, logical_handle=None,
                     actor=None, detail=None, created_at=None):
        self._execute(
            """
            INSERT INTO mint_audit(
                event, outcome, agent_uuid, logical_handle, actor, detail, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event,
                outcome,
                agent_uuid,
                logical_handle,
                actor,
                json.dumps(detail or {}, sort_keys=True),
                to_iso8601(created_at or utcnow()),
            ),
        )

    def list_audit(self, logical_handle=None, limit=100):
        if logical_handle:
            rows = self._query_all(
                "SELECT * FROM mint_audit WHERE logical_handle = ? "
                "ORDER BY audit_id DESC LIMIT ?",
                (logical_handle, int(limit)),
            )
        else:
            rows = self._query_all(
                "SELECT * FROM mint_audit ORDER BY audit_id DESC LIMIT ?",
                (int(limit),),
            )
        for row in rows:
            row["detail"] = _loads(row["detail"], {})
        return rows
