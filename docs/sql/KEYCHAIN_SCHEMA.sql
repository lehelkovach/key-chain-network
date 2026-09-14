-- KeyChain Network Postgres schema.
--
-- The shipped service runs on SQLite (see keychain/store.py), which is the right
-- default for a low-write authority. This file is the equivalent Postgres DDL for
-- a deployment that needs more than one KeyChain process, and it is written to sit
-- alongside the IAC-Bus ACP v2 schema (iac-bus/docs/sql/ACP_V2_SCHEMA.sql) in the
-- same database if you want one: the agents table here is a superset of the one
-- there, adding key material, certificates and custody.
--
-- Relationship to the ACP v2 draft:
--   * agents.agent_uuid, brand, repo_locale, ordinal_path, logical_handle,
--     parent_agent_uuid, role and status carry the same meaning and constraints.
--   * agent_endpoints keys on (agent_uuid, medium, session_id) as the draft does,
--     but does NOT mark endpoint_handle unique. The draft marks it unique while
--     also allowing several sessions per medium, and those cannot both hold:
--     every session of one agent on one medium derives the same
--     <logical-handle>@<medium>.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Trust roots
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS trust_roots (
    root_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9._-]+$'),
    key_id             TEXT NOT NULL UNIQUE,
    public_jwk         JSONB NOT NULL,
    -- AES-256-GCM blob under KEYCHAIN_MASTER_KEY, or NULL when the private key is
    -- held outside this deployment (offline human key, HSM).
    sealed_private_key TEXT,
    cert_id            UUID NOT NULL,
    capabilities       JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    is_default         BOOLEAN NOT NULL DEFAULT FALSE,
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one default root.
CREATE UNIQUE INDEX IF NOT EXISTS uq_trust_roots_default
    ON trust_roots(is_default) WHERE is_default;

-- ---------------------------------------------------------------------------
-- Certificates
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS certificates (
    cert_id        UUID PRIMARY KEY,
    cert_type      TEXT NOT NULL CHECK (cert_type IN ('root', 'agent')),
    subject_ref    TEXT NOT NULL,
    subject_key_id TEXT NOT NULL,
    -- NULL for a self-signed root. Following this column upward reconstructs the
    -- chain a relying party verifies.
    issuer_cert_id UUID REFERENCES certificates(cert_id) ON DELETE RESTRICT,
    issuer_key_id  TEXT NOT NULL,
    root_key_id    TEXT NOT NULL,
    -- The signed document verbatim. Never rewrite it: the signature covers every
    -- member, so any edit invalidates it.
    document       JSONB NOT NULL,
    issued_at      TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_certificates_subject ON certificates(subject_ref);
CREATE INDEX IF NOT EXISTS idx_certificates_subject_key
    ON certificates(subject_key_id);
CREATE INDEX IF NOT EXISTS idx_certificates_issuer ON certificates(issuer_cert_id);
CREATE INDEX IF NOT EXISTS idx_certificates_root ON certificates(root_key_id);

ALTER TABLE trust_roots
    DROP CONSTRAINT IF EXISTS fk_trust_roots_cert;
ALTER TABLE trust_roots
    ADD CONSTRAINT fk_trust_roots_cert
    FOREIGN KEY (cert_id) REFERENCES certificates(cert_id) ON DELETE RESTRICT;

-- ---------------------------------------------------------------------------
-- Agents
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agents (
    agent_uuid         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brand              TEXT NOT NULL CHECK (brand ~ '^[a-z0-9_-]+$'),
    repo_locale        TEXT NOT NULL CHECK (repo_locale ~ '^[a-z0-9_.-]+$'),
    ordinal_path       TEXT NOT NULL CHECK (ordinal_path ~ '^([0-9]+)(-[0-9]+)*$'),
    logical_handle     TEXT NOT NULL UNIQUE
        CHECK (logical_handle ~ '^agent:[a-z0-9_-]+\.[a-z0-9_.-]+\.[0-9]+(-[0-9]+)*$'),
    parent_agent_uuid  UUID REFERENCES agents(agent_uuid) ON DELETE SET NULL,
    role               TEXT NOT NULL DEFAULT 'worker' CHECK (role ~ '^[a-z0-9_-]+$'),
    status             TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'idle', 'blocked', 'revoked', 'terminated')),
    root_id            UUID NOT NULL REFERENCES trust_roots(root_id) ON DELETE RESTRICT,
    -- One key backs exactly one identity, for the lifetime of that identity.
    key_id             TEXT NOT NULL UNIQUE,
    public_jwk         JSONB NOT NULL,
    sealed_private_key TEXT,
    custody            TEXT NOT NULL DEFAULT 'agent'
        CHECK (custody IN ('agent', 'keychain')),
    cert_id            UUID NOT NULL REFERENCES certificates(cert_id) ON DELETE RESTRICT,
    capabilities       JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- custody='keychain' means KeyChain holds the key and can sign for the agent;
    -- custody='agent' means it must not have a copy.
    CONSTRAINT chk_agents_custody CHECK (
        (custody = 'keychain' AND sealed_private_key IS NOT NULL)
        OR (custody = 'agent' AND sealed_private_key IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_agents_parent ON agents(parent_agent_uuid);
CREATE INDEX IF NOT EXISTS idx_agents_namespace
    ON agents(brand, repo_locale, ordinal_path);
CREATE INDEX IF NOT EXISTS idx_agents_root ON agents(root_id);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);

-- ---------------------------------------------------------------------------
-- Endpoints (presence per medium/session)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agent_endpoints (
    endpoint_uuid   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_uuid      UUID NOT NULL REFERENCES agents(agent_uuid) ON DELETE CASCADE,
    medium          TEXT NOT NULL
        CHECK (medium IN ('web', 'slack', 'ide', 'api', 'automation', 'other')),
    endpoint_handle TEXT NOT NULL,
    session_id      TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen_at    TIMESTAMPTZ,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_uuid, medium, session_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_endpoints_agent ON agent_endpoints(agent_uuid);
CREATE INDEX IF NOT EXISTS idx_agent_endpoints_handle
    ON agent_endpoints(endpoint_handle);
CREATE INDEX IF NOT EXISTS idx_agent_endpoints_seen
    ON agent_endpoints(medium, is_active, last_seen_at DESC);

-- ---------------------------------------------------------------------------
-- Revocations
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS revocations (
    revocation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_kind  TEXT NOT NULL CHECK (subject_kind IN ('agent', 'root', 'certificate')),
    subject_ref   TEXT NOT NULL,
    agent_uuid    UUID REFERENCES agents(agent_uuid) ON DELETE SET NULL,
    cert_id       UUID REFERENCES certificates(cert_id) ON DELETE SET NULL,
    key_id        TEXT,
    reason        TEXT,
    revoked_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subject_kind, subject_ref)
);

CREATE INDEX IF NOT EXISTS idx_revocations_key ON revocations(key_id);
CREATE INDEX IF NOT EXISTS idx_revocations_cert ON revocations(cert_id);
CREATE INDEX IF NOT EXISTS idx_revocations_time ON revocations(revoked_at DESC);

-- ---------------------------------------------------------------------------
-- Mint audit trail (append only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS mint_audit (
    audit_id       BIGSERIAL PRIMARY KEY,
    event          TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    agent_uuid     UUID,
    logical_handle TEXT,
    actor          TEXT,
    detail         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mint_audit_handle ON mint_audit(logical_handle);
CREATE INDEX IF NOT EXISTS idx_mint_audit_created ON mint_audit(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mint_audit_agent ON mint_audit(agent_uuid);

-- ---------------------------------------------------------------------------
-- Convenience view: the identity facts IAC-Bus needs for routing and history
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW active_agent_identities AS
SELECT
    a.agent_uuid,
    a.logical_handle,
    a.brand,
    a.repo_locale,
    a.ordinal_path,
    a.role,
    a.status,
    a.parent_agent_uuid,
    a.capabilities,
    a.key_id,
    a.public_jwk,
    r.key_id AS root_key_id,
    a.created_at
FROM agents a
JOIN trust_roots r ON r.root_id = a.root_id
WHERE a.status <> 'revoked'
  AND NOT EXISTS (
      SELECT 1 FROM revocations v WHERE v.key_id = a.key_id
  );
