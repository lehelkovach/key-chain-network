"""The minting authority.

:class:`KeyChainService` is the whole product in one object: it bootstraps trust
roots, mints agent identities that satisfy the IAC-Bus ACP v2 contract, issues
and verifies capability tokens, and cascades revocation down a subtree.

Two invariants drive the design.

*A handle is bound to a key for life.* Re-minting an existing handle is
idempotent and returns the original ``agent_uuid`` and certificate; it never
rebinds the identity to different key material. Anything that would change the
identity behind a handle is a ``409`` with a specific ``conflict_code`` rather
than a silent overwrite.

*Authority only ever narrows going down the chain.* An agent's capabilities are
attenuated against its issuer's, and a token's capabilities against the agent's
certificate, so a relying party can stop at the first link it recognises.
"""

import datetime
import logging

from . import capabilities as caps
from . import certificates, identity, keys, tokens
from .canonical import from_epoch, to_iso8601, utcnow
from .config import ISSUER_AUTO, ISSUER_PARENT, ISSUER_ROOT, KeyChainConfig
from .errors import (
    ConflictError,
    CustodyError,
    NotFoundError,
    RevokedError,
    ValidationError,
)
from .store import (
    CUSTODY_AGENT,
    CUSTODY_KEYCHAIN,
    CUSTODY_MODES,
    STATUS_ACTIVE,
    STATUS_REVOKED,
    SUBJECT_KIND_AGENT,
    SUBJECT_KIND_ROOT,
    KeyChainStore,
)

logger = logging.getLogger("keychain")

DEFAULT_MINT_MEDIUM = "api"

#: Conflict codes returned when a mint would change an existing identity.
CONFLICT_PARENT_MISMATCH = "HANDLE_PARENT_MISMATCH"
CONFLICT_IDENTITY_MISMATCH = "HANDLE_IDENTITY_MISMATCH"
CONFLICT_ROLE_MISMATCH = "HANDLE_ROLE_MISMATCH"
CONFLICT_KEY_MISMATCH = "HANDLE_KEY_MISMATCH"
CONFLICT_ROOT_MISMATCH = "HANDLE_ROOT_MISMATCH"


class MintResult:
    """A minted or resolved identity, plus how it was obtained."""

    def __init__(self, agent, certificate, chain, root, created, private_jwk=None,
                 endpoint=None):
        self.agent = agent
        self.certificate = certificate
        self.chain = chain
        self.root = root
        self.created = created
        self.private_jwk = private_jwk
        self.endpoint = endpoint

    @property
    def status_code(self):
        return 201 if self.created else 200

    def to_dict(self, include_chain=True, include_private_key=True):
        agent = self.agent
        payload = {
            "created": self.created,
            "agent_uuid": agent["agent_uuid"],
            "logical_handle": agent["logical_handle"],
            "brand": agent["brand"],
            "repo_locale": agent["repo_locale"],
            "ordinal_path": agent["ordinal_path"],
            "role": agent["role"],
            "status": agent["status"],
            "parent_agent_uuid": agent["parent_agent_uuid"],
            "capabilities": agent["capabilities"],
            "custody": agent["custody"],
            "key_id": agent["key_id"],
            "public_key": agent["public_jwk"],
            "certificate": self.certificate,
            "trust_root": {
                "root_id": self.root["root_id"],
                "name": self.root["name"],
                "key_id": self.root["key_id"],
            },
            "created_at": agent["created_at"],
        }
        if self.endpoint is not None:
            payload["endpoint_handle"] = self.endpoint["endpoint_handle"]
            payload["medium"] = self.endpoint["medium"]
            payload["session_id"] = self.endpoint["session_id"]
        if include_chain:
            payload["certificate_chain"] = self.chain
        if include_private_key and self.private_jwk is not None:
            payload["private_key"] = self.private_jwk
            payload["private_key_notice"] = (
                "Store this key now. KeyChain does not retain it and cannot "
                "return it again."
            )
        return payload

    def to_acp_register_response(self):
        """The exact shape ACP v2 ``POST /agents/register`` promises, plus extras.

        The four documented fields come first and keep their meaning, so an
        IAC-Bus client written against ACP v2 works unchanged; the KeyChain
        additions (key, certificate, capabilities) are additive.
        """
        response = {
            "agent_uuid": self.agent["agent_uuid"],
            "logical_handle": self.agent["logical_handle"],
            "endpoint_handle": (
                self.endpoint["endpoint_handle"] if self.endpoint else None
            ),
            "created": self.created,
        }
        response["keychain"] = {
            "key_id": self.agent["key_id"],
            "public_key": self.agent["public_jwk"],
            "capabilities": self.agent["capabilities"],
            "role": self.agent["role"],
            "parent_agent_uuid": self.agent["parent_agent_uuid"],
            "trust_root_key_id": self.root["key_id"],
            "certificate": self.certificate,
            "certificate_chain": self.chain,
        }
        if self.private_jwk is not None:
            response["keychain"]["private_key"] = self.private_jwk
        return response


class KeyChainService:
    def __init__(self, store=None, key_wrapper=None, config=None):
        self.config = config or KeyChainConfig()
        self.store = store if store is not None else KeyChainStore(self.config.db_path)
        if key_wrapper is None:
            key_wrapper = keys.key_wrapper_from_env()
        self.key_wrapper = key_wrapper

    # -- trust roots ---------------------------------------------------------

    def bootstrap_root(self, name=None, capabilities=None, ttl_seconds=None,
                       make_default=None, metadata=None):
        """Create a trust root and its self-signed certificate.

        A root is the anchor a relying party pins: IAC-Bus is configured with a
        root ``key_id`` and will accept any chain that terminates there.
        """
        name = identity.normalize_slug(name or self.config.default_root_name, "name")
        if self.store.get_root_by_name(name) is not None:
            raise ConflictError(
                "trust root %r already exists" % name, conflict_code="ROOT_EXISTS"
            )

        capabilities = caps.normalize_capabilities(
            capabilities or caps.ROOT_CAPABILITIES
        )
        issued_at = utcnow()
        ttl = self.config.root_cert_ttl_seconds if ttl_seconds is None else ttl_seconds
        expires_at = issued_at + datetime.timedelta(seconds=ttl) if ttl else None

        private_key = keys.generate_private_key()
        jwk = keys.public_jwk(private_key.public_key())
        root_id = identity.mint_agent_uuid(
            "agent:root.%s.0" % name.replace(".", "-"),
            mode=identity.UUID_MODE_DERIVED,
            namespace_seed="keychain-root|%s" % jwk["kid"],
        )
        subject = certificates.build_root_subject(root_id, name, jwk)
        certificate = certificates.issue_certificate(
            certificates.CERT_TYPE_ROOT,
            subject,
            capabilities,
            private_key,
            issuer_certificate=None,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        sealed = self.key_wrapper.wrap(
            keys.private_key_bytes(private_key), aad=jwk["kid"]
        )
        self.store.insert_certificate(certificate, root_key_id=jwk["kid"])
        is_default = (
            make_default
            if make_default is not None
            else self.store.get_default_root() is None
        )
        root = self.store.insert_root(
            name=name,
            key_id=jwk["kid"],
            public_jwk=jwk,
            sealed_private_key=sealed,
            cert_id=certificate["cert_id"],
            capabilities=capabilities,
            is_default=is_default,
            metadata=metadata,
            root_id=root_id,
        )
        self.store.append_audit(
            "root.bootstrap", "created", logical_handle="root:%s" % name,
            detail={"key_id": jwk["kid"], "root_id": root_id},
        )
        logger.info("bootstrapped trust root %s (key_id=%s)", name, jwk["kid"])
        return root, certificate

    def resolve_root(self, reference=None):
        """Resolve a root by id, name or key id, falling back to the default."""
        if reference:
            for lookup in (
                self.store.get_root,
                self.store.get_root_by_name,
                self.store.get_root_by_key_id,
            ):
                root = lookup(reference)
                if root is not None:
                    return root
            raise NotFoundError("trust root not found: %s" % reference)
        root = self.store.get_default_root()
        if root is not None:
            return root
        if self.config.auto_bootstrap_root:
            root, _certificate = self.bootstrap_root()
            return root
        raise NotFoundError(
            "no trust root configured; bootstrap one with POST /trust/roots "
            "or set KEYCHAIN_AUTO_BOOTSTRAP_ROOT=1"
        )

    def ensure_root(self):
        """Make sure a default root exists when the instance is allowed to make one.

        Called at startup so that discovery endpoints (``/health``, JWKS, public
        roots) describe a usable instance instead of an empty one. Returns ``None``
        when no root exists and auto-bootstrap is off, rather than raising: a
        KeyChain that is waiting for an operator to create a root should still
        serve health checks.
        """
        try:
            return self.resolve_root()
        except NotFoundError:
            return None

    def trusted_root_key_ids(self):
        return [root["key_id"] for root in self.store.list_roots()]

    def jwks(self):
        """Public keys a relying party may need to verify authority-signed tokens."""
        return {
            "keys": [
                dict(root["public_jwk"], use="sig", alg=keys.JWS_ALGORITHM)
                for root in self.store.list_roots()
            ]
        }

    def _root_private_key(self, root):
        sealed = root.get("sealed_private_key")
        if not sealed:
            raise CustodyError(
                "trust root %s has no private key in custody; it cannot sign"
                % root["name"]
            )
        return keys.private_key_from_bytes(
            self.key_wrapper.unwrap(sealed, aad=root["key_id"])
        )

    def _agent_private_key(self, agent):
        sealed = agent.get("sealed_private_key")
        if not sealed:
            raise CustodyError(
                "agent %s holds its own private key; KeyChain cannot sign on its "
                "behalf" % agent["logical_handle"]
            )
        return keys.private_key_from_bytes(
            self.key_wrapper.unwrap(sealed, aad=agent["key_id"])
        )

    # -- mint ----------------------------------------------------------------

    def _normalize_mint_request(self, payload, require_medium=False,
                                default_medium=DEFAULT_MINT_MEDIUM):
        """Validate a mint request, collecting every problem before failing."""
        if not isinstance(payload, dict):
            raise ValidationError("request body must be a JSON object")

        errors = []
        request = {}

        try:
            request["role"] = identity.normalize_role(payload.get("role") or "worker")
        except ValidationError as exc:
            errors.append(str(exc))
            request["role"] = "worker"

        medium = payload.get("medium")
        if medium is None:
            if require_medium:
                errors.append("medium is required")
            medium = default_medium
        try:
            request["medium"] = identity.normalize_medium(medium)
        except ValidationError as exc:
            errors.append(str(exc))
            request["medium"] = default_medium

        try:
            request["session_id"] = identity.normalize_session_id(
                payload.get("session_id")
            )
        except ValidationError as exc:
            errors.append(str(exc))
            request["session_id"] = None

        brand = payload.get("brand")
        repo_locale = payload.get("repo_locale")
        ordinal_path = payload.get("ordinal_path")
        logical_handle = payload.get("logical_handle")

        if logical_handle is not None:
            try:
                parsed = identity.parse_logical_handle(logical_handle)
            except ValidationError as exc:
                errors.append(str(exc))
                parsed = None
            if parsed is not None:
                # Explicit components must agree with the handle they claim to
                # describe; a mismatch means the caller is confused about which
                # identity it is asking for.
                for supplied, derived, field in zip(
                    (brand, repo_locale, ordinal_path), parsed,
                    ("brand", "repo_locale", "ordinal_path"),
                ):
                    if supplied is None:
                        continue
                    try:
                        normalized = {
                            "brand": identity.normalize_brand,
                            "repo_locale": identity.normalize_repo_locale,
                            "ordinal_path": identity.validate_ordinal_path,
                        }[field](supplied)
                    except ValidationError as exc:
                        errors.append(str(exc))
                        continue
                    if normalized != derived:
                        errors.append(
                            "%s %r contradicts logical_handle %r"
                            % (field, normalized, logical_handle)
                        )
                request["brand"], request["repo_locale"] = parsed[0], parsed[1]
                request["ordinal_path"] = parsed[2]
        else:
            if brand is None:
                errors.append("brand is required")
            if repo_locale is None:
                errors.append("repo_locale is required")
            for field, value, normalizer in (
                ("brand", brand, identity.normalize_brand),
                ("repo_locale", repo_locale, identity.normalize_repo_locale),
            ):
                if value is None:
                    continue
                try:
                    request[field] = normalizer(value)
                except ValidationError as exc:
                    errors.append(str(exc))
            if ordinal_path is not None:
                try:
                    request["ordinal_path"] = identity.validate_ordinal_path(
                        ordinal_path
                    )
                except ValidationError as exc:
                    errors.append(str(exc))
            else:
                request["ordinal_path"] = None

        parent_reference = payload.get("parent_agent_uuid")
        parent_handle = payload.get("parent_handle")
        if parent_reference is not None:
            try:
                request["parent_agent_uuid"] = identity.validate_agent_uuid(
                    parent_reference
                )
            except ValidationError as exc:
                errors.append(str(exc))
                request["parent_agent_uuid"] = None
        else:
            request["parent_agent_uuid"] = None
        if parent_handle is not None:
            try:
                request["parent_handle"] = identity.validate_logical_handle(
                    parent_handle
                )
            except ValidationError as exc:
                errors.append(str(exc))
                request["parent_handle"] = None
        else:
            request["parent_handle"] = None

        custody = str(payload.get("custody") or CUSTODY_AGENT).strip().lower()
        if custody not in CUSTODY_MODES:
            errors.append("custody must be one of %s" % ", ".join(CUSTODY_MODES))
            custody = CUSTODY_AGENT
        request["custody"] = custody

        issuer_mode = str(
            payload.get("issuer") or self.config.issuer_mode
        ).strip().lower()
        if issuer_mode not in (ISSUER_AUTO, ISSUER_ROOT, ISSUER_PARENT):
            errors.append(
                "issuer must be one of %s"
                % ", ".join((ISSUER_AUTO, ISSUER_ROOT, ISSUER_PARENT))
            )
            issuer_mode = ISSUER_AUTO
        request["issuer_mode"] = issuer_mode

        if payload.get("capabilities") is not None:
            try:
                request["capabilities"] = caps.normalize_capabilities(
                    payload["capabilities"]
                )
            except ValidationError as exc:
                errors.append(str(exc))
                request["capabilities"] = None
        else:
            request["capabilities"] = None

        public_key = payload.get("public_key")
        if public_key is not None:
            try:
                keys.load_public_jwk(public_key)
                request["public_key"] = keys.public_jwk(
                    keys.load_public_jwk(public_key)
                )
            except ValidationError as exc:
                errors.append("public_key is invalid: %s" % exc)
                request["public_key"] = None
        else:
            request["public_key"] = None

        ttl_seconds = payload.get("ttl_seconds")
        if ttl_seconds is not None:
            if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
                errors.append("ttl_seconds must be an integer")
                ttl_seconds = None
            elif ttl_seconds <= 0:
                errors.append("ttl_seconds must be positive")
                ttl_seconds = None
        request["ttl_seconds"] = ttl_seconds

        metadata = payload.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            errors.append("metadata must be an object")
            metadata = None
        request["metadata"] = metadata or {}
        request["root"] = payload.get("root")

        if errors:
            raise ValidationError("invalid mint request", details=sorted(set(errors)))
        return request

    def _resolve_parent(self, request):
        """Find the parent agent named by a mint request, if any."""
        parent = None
        if request["parent_agent_uuid"]:
            parent = self.store.get_agent(request["parent_agent_uuid"])
            if parent is None:
                raise NotFoundError("parent agent not found")
        if request["parent_handle"]:
            by_handle = self.store.get_agent_by_handle(request["parent_handle"])
            if by_handle is None:
                raise NotFoundError("parent agent not found")
            if parent is not None and by_handle["agent_uuid"] != parent["agent_uuid"]:
                raise ValidationError(
                    "parent_agent_uuid and parent_handle refer to different agents"
                )
            parent = by_handle
        if parent is not None and parent["status"] == STATUS_REVOKED:
            raise RevokedError(
                "parent agent %s is revoked" % parent["logical_handle"]
            )
        return parent

    def _resolve_ordinal_path(self, request, parent):
        """Fill in the ordinal path, allocating the next free child when omitted."""
        ordinal_path = request.get("ordinal_path")
        if ordinal_path is None:
            if parent is None:
                return identity.MASTER_ORDINAL
            if (
                parent["brand"] != request["brand"]
                or parent["repo_locale"] != request["repo_locale"]
            ):
                # Cross-namespace delegation mints the master of the new
                # namespace; ordinal paths do not span namespaces.
                return identity.MASTER_ORDINAL
            index = self.store.next_child_ordinal_index(
                request["brand"], request["repo_locale"], parent["ordinal_path"]
            )
            return identity.child_ordinal_path(parent["ordinal_path"], index)
        if identity.ordinal_depth(ordinal_path) > 1 and parent is None:
            raise ValidationError(
                "invalid mint request",
                details=[
                    "ordinal_path %s is not a master ordinal, so a parent is "
                    "required (parent_agent_uuid or parent_handle)" % ordinal_path
                ],
            )
        return ordinal_path

    def _select_issuer(self, request, parent, root):
        """Decide who signs the new certificate and return the signing context.

        ``auto`` prefers the parent agent, which is what makes the chain a real
        delegation chain rather than a flat list of root-signed certificates. It
        falls back to the root when the parent's private key is not in KeyChain
        custody, because the parent's own machine holds it.
        """
        mode = request["issuer_mode"]
        if mode == ISSUER_ROOT or parent is None:
            if mode == ISSUER_PARENT and parent is None:
                raise ValidationError(
                    "issuer=parent requires a parent agent"
                )
            return (
                self._root_private_key(root),
                self.store.get_certificate(root["cert_id"]),
                root["capabilities"],
                "root:%s" % root["name"],
            )

        parent_certificate = self.store.get_certificate(parent["cert_id"])
        if parent_certificate is None:
            raise NotFoundError(
                "parent certificate not found for %s" % parent["logical_handle"]
            )
        if parent["custody"] != CUSTODY_KEYCHAIN or not parent.get(
            "sealed_private_key"
        ):
            if mode == ISSUER_PARENT:
                raise CustodyError(
                    "issuer=parent requires the parent private key in KeyChain "
                    "custody; %s was minted with custody=agent"
                    % parent["logical_handle"]
                )
            return (
                self._root_private_key(root),
                self.store.get_certificate(root["cert_id"]),
                root["capabilities"],
                "root:%s" % root["name"],
            )
        return (
            self._agent_private_key(parent),
            parent_certificate,
            parent["capabilities"],
            parent["logical_handle"],
        )

    def _check_idempotent_mint(self, existing, request, parent, root):
        """Validate that a repeat mint describes the same identity.

        Implements the ACP v2 ``/agents/register`` conflict matrix. The handle is
        unique, so brand/repo/ordinal can only disagree when the caller supplied
        components that contradict the stored row; the check stays anyway because
        a stored row that no longer derives its own handle is a corruption we want
        to surface loudly rather than serve.
        """
        if existing["status"] == STATUS_REVOKED:
            raise ConflictError(
                "agent %s is revoked and cannot be re-minted"
                % existing["logical_handle"],
                conflict_code="HANDLE_REVOKED",
                existing_agent_uuid=existing["agent_uuid"],
            )
        for field in ("brand", "repo_locale", "ordinal_path"):
            if existing[field] != request[field]:
                raise ConflictError(
                    "agent registration conflict",
                    conflict_code=CONFLICT_IDENTITY_MISMATCH,
                    existing_agent_uuid=existing["agent_uuid"],
                    details=[
                        "%s: existing %r, requested %r"
                        % (field, existing[field], request[field])
                    ],
                )
        requested_parent = parent["agent_uuid"] if parent else None
        if requested_parent is not None and existing["parent_agent_uuid"] != (
            requested_parent
        ):
            raise ConflictError(
                "agent registration conflict",
                conflict_code=CONFLICT_PARENT_MISMATCH,
                existing_agent_uuid=existing["agent_uuid"],
                details=[
                    "parent_agent_uuid: existing %r, requested %r"
                    % (existing["parent_agent_uuid"], requested_parent)
                ],
            )
        if existing["role"] != request["role"]:
            raise ConflictError(
                "agent registration conflict",
                conflict_code=CONFLICT_ROLE_MISMATCH,
                existing_agent_uuid=existing["agent_uuid"],
                details=[
                    "role: existing %r, requested %r"
                    % (existing["role"], request["role"])
                ],
            )
        if request["public_key"] is not None and request["public_key"]["kid"] != (
            existing["key_id"]
        ):
            raise ConflictError(
                "agent registration conflict",
                conflict_code=CONFLICT_KEY_MISMATCH,
                existing_agent_uuid=existing["agent_uuid"],
                details=[
                    "handle %s is already bound to key %s"
                    % (existing["logical_handle"], existing["key_id"])
                ],
            )
        if existing["root_id"] != root["root_id"]:
            raise ConflictError(
                "agent registration conflict",
                conflict_code=CONFLICT_ROOT_MISMATCH,
                existing_agent_uuid=existing["agent_uuid"],
                details=[
                    "trust root: existing %r, requested %r"
                    % (existing["root_id"], root["root_id"])
                ],
            )

    def mint_agent(self, payload, require_medium=False, actor=None):
        """Mint (or idempotently resolve) an agent identity.

        Returns a :class:`MintResult` whose ``created`` flag distinguishes a fresh
        mint (HTTP 201) from an idempotent resolve (HTTP 200).
        """
        request = self._normalize_mint_request(payload, require_medium=require_medium)
        root = self.resolve_root(request["root"])
        parent = self._resolve_parent(request)
        request["ordinal_path"] = self._resolve_ordinal_path(request, parent)
        logical_handle = identity.build_logical_handle(
            request["brand"], request["repo_locale"], request["ordinal_path"]
        )

        existing = self.store.get_agent_by_handle(logical_handle)
        if existing is not None:
            self._check_idempotent_mint(existing, request, parent, root)
            endpoint, _created = self.store.upsert_endpoint(
                existing["agent_uuid"],
                request["medium"],
                identity.build_endpoint_handle(logical_handle, request["medium"]),
                session_id=request["session_id"],
            )
            self.store.append_audit(
                "agent.mint", "idempotent",
                agent_uuid=existing["agent_uuid"],
                logical_handle=logical_handle,
                actor=actor,
                detail={"medium": request["medium"]},
            )
            return MintResult(
                agent=existing,
                certificate=self.store.get_certificate(existing["cert_id"]),
                chain=self.store.get_certificate_chain(existing["cert_id"]),
                root=self.store.get_root(existing["root_id"]),
                created=False,
                endpoint=endpoint,
            )

        signing_key, issuer_certificate, issuer_capabilities, issuer_ref = (
            self._select_issuer(request, parent, root)
        )
        requested_capabilities = (
            request["capabilities"]
            if request["capabilities"] is not None
            else caps.default_capabilities_for_role(request["role"])
        )
        granted_capabilities = caps.attenuate(
            requested_capabilities, issuer_capabilities
        )

        private_key = None
        if request["public_key"] is not None:
            public_jwk = request["public_key"]
        else:
            private_key = keys.generate_private_key()
            public_jwk = keys.public_jwk(private_key.public_key())
        if self.store.get_agent_by_key_id(public_jwk["kid"]) is not None:
            raise ConflictError(
                "public key %s is already bound to another identity"
                % public_jwk["kid"],
                conflict_code=CONFLICT_KEY_MISMATCH,
            )

        agent_uuid = identity.mint_agent_uuid(
            logical_handle,
            mode=self.config.uuid_mode,
            namespace_seed=root["key_id"],
        )
        subject = certificates.build_agent_subject(
            agent_uuid,
            logical_handle,
            request["role"],
            public_jwk,
            parent_agent_uuid=parent["agent_uuid"] if parent else None,
        )
        issued_at = utcnow()
        ttl = (
            request["ttl_seconds"]
            if request["ttl_seconds"] is not None
            else self.config.agent_cert_ttl_seconds
        )
        expires_at = issued_at + datetime.timedelta(seconds=ttl) if ttl else None
        certificate = certificates.issue_certificate(
            certificates.CERT_TYPE_AGENT,
            subject,
            granted_capabilities,
            signing_key,
            issuer_certificate=issuer_certificate,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        self.store.insert_certificate(certificate, root_key_id=root["key_id"])

        sealed_private_key = None
        returned_private_jwk = None
        if private_key is not None:
            if request["custody"] == CUSTODY_KEYCHAIN:
                sealed_private_key = self.key_wrapper.wrap(
                    keys.private_key_bytes(private_key), aad=public_jwk["kid"]
                )
            else:
                # custody=agent: hand the key over once and keep only the public
                # half, so a KeyChain compromise cannot impersonate the agent.
                returned_private_jwk = keys.private_jwk(private_key)

        agent = self.store.insert_agent(
            {
                "agent_uuid": agent_uuid,
                "brand": request["brand"],
                "repo_locale": request["repo_locale"],
                "ordinal_path": request["ordinal_path"],
                "logical_handle": logical_handle,
                "parent_agent_uuid": parent["agent_uuid"] if parent else None,
                "role": request["role"],
                "status": STATUS_ACTIVE,
                "root_id": root["root_id"],
                "key_id": public_jwk["kid"],
                "public_jwk": public_jwk,
                "sealed_private_key": sealed_private_key,
                "custody": (
                    CUSTODY_KEYCHAIN
                    if sealed_private_key
                    else CUSTODY_AGENT
                ),
                "cert_id": certificate["cert_id"],
                "capabilities": granted_capabilities,
                "metadata": request["metadata"],
                "created_at": to_iso8601(issued_at),
                "updated_at": to_iso8601(issued_at),
            }
        )
        endpoint, _created = self.store.upsert_endpoint(
            agent_uuid,
            request["medium"],
            identity.build_endpoint_handle(logical_handle, request["medium"]),
            session_id=request["session_id"],
        )
        self.store.append_audit(
            "agent.mint", "created",
            agent_uuid=agent_uuid,
            logical_handle=logical_handle,
            actor=actor,
            detail={
                "issuer": issuer_ref,
                "medium": request["medium"],
                "capabilities": granted_capabilities,
                "custody": agent["custody"],
            },
        )
        logger.info(
            "minted %s (agent_uuid=%s) issued by %s",
            logical_handle, agent_uuid, issuer_ref,
        )
        return MintResult(
            agent=agent,
            certificate=certificate,
            chain=self.store.get_certificate_chain(certificate["cert_id"]),
            root=root,
            created=True,
            private_jwk=returned_private_jwk,
            endpoint=endpoint,
        )

    # -- lifecycle -----------------------------------------------------------

    def heartbeat(self, agent_uuid, medium, session_id=None):
        agent = self.require_agent(agent_uuid)
        medium = identity.normalize_medium(medium)
        session_id = identity.normalize_session_id(session_id)
        endpoint = self.store.get_endpoint(agent["agent_uuid"], medium, session_id)
        if endpoint is None:
            endpoint, _created = self.store.upsert_endpoint(
                agent["agent_uuid"],
                medium,
                identity.build_endpoint_handle(agent["logical_handle"], medium),
                session_id=session_id,
                last_seen_at=utcnow(),
            )
            return endpoint
        return self.store.touch_endpoint(agent["agent_uuid"], medium, session_id)

    def require_agent(self, reference):
        """Resolve an agent by ``agent_uuid``, logical handle or endpoint handle.

        A reference that is not a well-formed identifier reads as "no such agent"
        rather than a validation failure, so a stray path segment produces a 404
        instead of a 400.
        """
        if not isinstance(reference, str) or not reference.strip():
            raise ValidationError("agent reference must be a non-empty string")
        reference = reference.strip()
        try:
            if reference.startswith(identity.LOGICAL_HANDLE_PREFIX):
                if "@" in reference:
                    reference = identity.parse_endpoint_handle(reference)[0]
                agent = self.store.get_agent_by_handle(
                    identity.validate_logical_handle(reference)
                )
            else:
                agent = self.store.get_agent(identity.validate_agent_uuid(reference))
        except ValidationError as exc:
            raise NotFoundError("agent not found: %s" % reference,
                                details=[str(exc)]) from exc
        if agent is None:
            raise NotFoundError("agent not found: %s" % reference)
        return agent

    def describe_agent(self, reference, include_chain=True):
        agent = self.require_agent(reference)
        payload = {
            "agent_uuid": agent["agent_uuid"],
            "logical_handle": agent["logical_handle"],
            "brand": agent["brand"],
            "repo_locale": agent["repo_locale"],
            "ordinal_path": agent["ordinal_path"],
            "role": agent["role"],
            "status": agent["status"],
            "parent_agent_uuid": agent["parent_agent_uuid"],
            "capabilities": agent["capabilities"],
            "custody": agent["custody"],
            "key_id": agent["key_id"],
            "public_key": agent["public_jwk"],
            "metadata": agent["metadata"],
            "created_at": agent["created_at"],
            "updated_at": agent["updated_at"],
            "endpoints": [
                {
                    "endpoint_handle": endpoint["endpoint_handle"],
                    "medium": endpoint["medium"],
                    "session_id": endpoint["session_id"],
                    "is_active": endpoint["is_active"],
                    "last_seen_at": endpoint["last_seen_at"],
                }
                for endpoint in self.store.list_endpoints(agent["agent_uuid"])
            ],
            "children": [
                child["logical_handle"]
                for child in self.store.list_children(agent["agent_uuid"])
            ],
            "trust_root": {
                "root_id": agent["root_id"],
                "key_id": (self.store.get_root(agent["root_id"]) or {}).get("key_id"),
            },
            "certificate": self.store.get_certificate(agent["cert_id"]),
        }
        if include_chain:
            payload["certificate_chain"] = self.store.get_certificate_chain(
                agent["cert_id"]
            )
        return payload

    def revoke_agent(self, reference, reason=None, cascade=True, actor=None):
        """Revoke an identity and, by default, everything minted beneath it.

        Cascading is the default because a compromised orchestrator can have
        minted children whose certificates chain through it; leaving those active
        would leave the attacker with working credentials.
        """
        agent = self.require_agent(reference)
        targets = [agent]
        if cascade:
            targets.extend(self.store.list_descendants(agent["agent_uuid"]))

        revoked = []
        for target in targets:
            if target["status"] != STATUS_REVOKED:
                self.store.update_agent_status(target["agent_uuid"], STATUS_REVOKED)
            self.store.deactivate_endpoints(target["agent_uuid"])
            self.store.forget_agent_private_key(target["agent_uuid"])
            self.store.insert_revocation(
                SUBJECT_KIND_AGENT,
                target["logical_handle"],
                reason=reason,
                agent_uuid=target["agent_uuid"],
                cert_id=target["cert_id"],
                key_id=target["key_id"],
            )
            self.store.append_audit(
                "agent.revoke", "revoked",
                agent_uuid=target["agent_uuid"],
                logical_handle=target["logical_handle"],
                actor=actor,
                detail={"reason": reason, "cascaded": target is not agent},
            )
            revoked.append(target["logical_handle"])
        logger.warning(
            "revoked %d identity(ies) rooted at %s", len(revoked),
            agent["logical_handle"],
        )
        return {
            "revoked": revoked,
            "agent_uuid": agent["agent_uuid"],
            "logical_handle": agent["logical_handle"],
            "cascade": cascade,
            "reason": reason,
        }

    def revoke_root(self, reference, reason=None, actor=None):
        root = self.resolve_root(reference)
        self.store.insert_revocation(
            SUBJECT_KIND_ROOT,
            "root:%s" % root["name"],
            reason=reason,
            cert_id=root["cert_id"],
            key_id=root["key_id"],
        )
        self.store.append_audit(
            "root.revoke", "revoked",
            logical_handle="root:%s" % root["name"],
            actor=actor,
            detail={"reason": reason},
        )
        return {"revoked": ["root:%s" % root["name"]], "key_id": root["key_id"]}

    # -- verification --------------------------------------------------------

    def _revocation_predicate(self):
        revoked_keys = self.store.revoked_key_ids()
        revoked_certs = self.store.revoked_cert_ids()

        def is_revoked(certificate):
            subject = certificate.get("subject") or {}
            return (
                subject.get("key_id") in revoked_keys
                or certificate.get("cert_id") in revoked_certs
            )

        return is_revoked

    def verify_chain(self, chain, check_revocation=True):
        return certificates.verify_chain(
            chain,
            self.trusted_root_key_ids(),
            is_revoked=self._revocation_predicate() if check_revocation else None,
        )

    def verify_certificate(self, certificate, check_revocation=True):
        """Verify a single certificate by rebuilding its chain from local storage."""
        if not isinstance(certificate, dict):
            raise ValidationError("certificate must be an object")
        cert_id = certificate.get("cert_id")
        chain = self.store.get_certificate_chain(cert_id) if cert_id else []
        if chain:
            # Trust the caller's copy of the leaf so a tampered document is
            # caught rather than silently replaced by the stored one.
            chain = [certificate] + chain[1:]
        else:
            chain = [certificate]
        return self.verify_chain(chain, check_revocation=check_revocation)

    # -- tokens --------------------------------------------------------------

    def issue_token(self, reference, audience=None, ttl_seconds=None,
                    capabilities=None, self_contained=None, actor=None):
        """Issue a capability token for an agent.

        A self-contained token embeds the certificate chain so relying parties can
        verify it offline, but it must be signed by the agent's own key. That is
        only possible when the key is in KeyChain custody, so ``self_contained``
        defaults to whichever mode the agent's custody allows: agents that hold
        their own key get an authority-signed token here and can mint
        self-contained ones locally with ``keychain_cli.py token --private-key``.
        """
        agent = self.require_agent(reference)
        if agent["status"] == STATUS_REVOKED:
            raise RevokedError("agent %s is revoked" % agent["logical_handle"])
        if self_contained is None:
            self_contained = agent["custody"] == CUSTODY_KEYCHAIN

        ttl_seconds = (
            self.config.token_ttl_seconds if ttl_seconds is None else ttl_seconds
        )
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise ValidationError("ttl_seconds must be an integer")
        if ttl_seconds > self.config.max_token_ttl_seconds:
            raise ValidationError(
                "ttl_seconds must not exceed %d" % self.config.max_token_ttl_seconds
            )

        granted = caps.attenuate(
            capabilities if capabilities is not None else agent["capabilities"],
            agent["capabilities"],
        )
        root = self.store.get_root(agent["root_id"])
        chain = self.store.get_certificate_chain(agent["cert_id"])
        subject = dict((chain[0].get("subject") or {}) if chain else {})
        endpoints = self.store.list_endpoints(agent["agent_uuid"])
        if endpoints:
            subject["endpoint_handle"] = endpoints[0]["endpoint_handle"]

        if self_contained:
            signing_key = self._agent_private_key(agent)
            token = tokens.issue_token(
                signing_key,
                subject,
                granted,
                audience=audience or self.config.default_audience,
                ttl_seconds=ttl_seconds,
                chain=chain,
                issuer_ref=agent["logical_handle"],
                root_key_id=root["key_id"],
            )
        else:
            token = tokens.issue_token(
                self._root_private_key(root),
                subject,
                granted,
                audience=audience or self.config.default_audience,
                ttl_seconds=ttl_seconds,
                issuer_ref="root:%s" % root["name"],
                root_key_id=root["key_id"],
            )
        self.store.append_audit(
            "token.issue", "issued",
            agent_uuid=agent["agent_uuid"],
            logical_handle=agent["logical_handle"],
            actor=actor,
            detail={
                "ttl_seconds": ttl_seconds,
                "capabilities": granted,
                "self_contained": self_contained,
            },
        )
        _header, payload, _signature, _signing_input = tokens.decode(token)
        if len(token) > tokens.HEADER_SAFE_BYTES:
            logger.warning(
                "token for %s is %d bytes, above the %d byte header-safe size; "
                "a proxy may reject it in an Authorization header",
                agent["logical_handle"], len(token), tokens.HEADER_SAFE_BYTES,
            )
        return {
            "token": token,
            "token_type": "Bearer",
            "expires_at": to_iso8601(from_epoch(payload.get("exp"))),
            "expires_in": ttl_seconds,
            "agent_uuid": agent["agent_uuid"],
            "logical_handle": agent["logical_handle"],
            "capabilities": granted,
            "jti": payload.get("jti"),
            "self_contained": self_contained,
            "token_bytes": len(token),
            "header_safe": len(token) <= tokens.HEADER_SAFE_BYTES,
        }

    def verify_token(self, token, audience=None, required_capabilities=None,
                     check_revocation=True):
        """Verify a token against local trust roots, then re-check its subject.

        The subject check catches revocations that the token itself cannot carry:
        an authority-signed token has no embedded chain, and even a self-contained
        one was signed before the revocation happened.
        """
        jwks = {key["kid"]: key for key in self.jwks()["keys"]}
        result = tokens.verify_token(
            token,
            trusted_root_key_ids=self.trusted_root_key_ids(),
            resolve_jwk=jwks.get,
            audience=audience,
            is_revoked=self._revocation_predicate() if check_revocation else None,
            required_capabilities=required_capabilities,
        )
        if check_revocation and result.payload:
            subject_uuid = result.payload.get("sub")
            agent = self.store.get_agent(subject_uuid) if subject_uuid else None
            if agent is not None and agent["status"] == STATUS_REVOKED:
                result.errors.append(
                    "token subject %s is revoked" % agent["logical_handle"]
                )
                result.valid = False
        return result

    # -- introspection -------------------------------------------------------

    def stats(self):
        roots = self.store.list_roots()
        return {
            "trust_roots": len(roots),
            "agents": self.store.count_agents(),
            "revocations": self.store.count_revocations(),
            "default_root_key_id": (
                (self.store.get_default_root() or {}).get("key_id")
            ),
        }
