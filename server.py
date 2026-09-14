#!/usr/bin/env python3
"""KeyChain Network HTTP service.

Mints agent identities for the IAC-Bus project. The surface is deliberately
close to IAC-Bus's own conventions -- Flask, bearer token on everything except
``/health``, JSON in and out -- so it slots into the same local loop, systemd
unit and deploy scripts.

Run locally:

    KEYCHAIN_ALLOW_PLAINTEXT_KEYS=1 KEYCHAIN_AUTO_BOOTSTRAP_ROOT=1 \\
    KEYCHAIN_API_TOKEN=devtoken KEYCHAIN_DB_PATH=:memory: python3 server.py
"""

import logging
import os

from flask import Flask, g, jsonify, request

from keychain.config import KeyChainConfig
from keychain.errors import KeyChainError, UnauthorizedError, ValidationError
from keychain.protocol import PROTOCOL_VERSION
from keychain.service import KeyChainService
from keychain.store import KeyChainStore
from version import VERSION

OPEN_PATHS = frozenset(
    {"/health", "/.well-known/keychain/jwks.json", "/.well-known/keychain/roots.json"}
)


def create_app(service=None, config=None):
    """Build the Flask app.

    Tests pass a pre-built ``service`` backed by an in-memory store; production
    lets the app build one from the environment.
    """
    config = config or (service.config if service is not None else KeyChainConfig.from_env())
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger = logging.getLogger("keychain.server")

    app = Flask(__name__)
    app.config["KEYCHAIN_CONFIG"] = config
    if service is None:
        service = KeyChainService(store=KeyChainStore(config.db_path), config=config)
    service.ensure_root()
    app.config["KEYCHAIN_SERVICE"] = service

    def current_service():
        return app.config["KEYCHAIN_SERVICE"]

    # -- auth ---------------------------------------------------------------

    @app.before_request
    def _authenticate():
        if request.path in OPEN_PATHS or request.method == "OPTIONS":
            return None
        if not config.api_token:
            g.actor = "anonymous"
            return None
        header = request.headers.get("Authorization", "")
        presented = header[7:].strip() if header.startswith("Bearer ") else ""
        if presented != config.api_token:
            return jsonify(UnauthorizedError("Unauthorized").to_dict()), 401
        g.actor = "operator"
        return None

    # -- error handling -----------------------------------------------------

    @app.errorhandler(KeyChainError)
    def _handle_keychain_error(error):
        if error.status >= 500:
            logger.exception("keychain error: %s", error.message)
        return jsonify(error.to_dict()), error.status

    @app.errorhandler(404)
    def _handle_404(_error):
        return jsonify({"error": "not found", "code": "not_found"}), 404

    @app.errorhandler(405)
    def _handle_405(_error):
        return jsonify({"error": "method not allowed", "code": "method_not_allowed"}), 405

    @app.errorhandler(Exception)
    def _handle_unexpected(error):
        logger.exception("unhandled error")
        return jsonify({"error": "internal error", "code": "internal_error"}), 500

    def body():
        payload = request.get_json(silent=True)
        if payload is None:
            raise ValidationError("request body must be a JSON object")
        if not isinstance(payload, dict):
            raise ValidationError("request body must be a JSON object")
        return payload

    def actor():
        return getattr(g, "actor", "anonymous")

    # -- health and discovery -----------------------------------------------

    @app.get("/health")
    def health():
        stats = current_service().stats()
        return jsonify(
            {
                "status": "ok",
                "service": "key-chain-network",
                "version": VERSION,
                "protocol": PROTOCOL_VERSION,
                "key_custody_sealed": current_service().key_wrapper.seals,
                "auth_required": bool(config.api_token),
                **stats,
            }
        )

    @app.get("/metrics")
    def metrics():
        return jsonify(
            {"version": VERSION, "config": config.to_dict(), **current_service().stats()}
        )

    @app.get("/.well-known/keychain/jwks.json")
    def jwks():
        return jsonify(current_service().jwks())

    @app.get("/.well-known/keychain/roots.json")
    def public_roots():
        """Trust anchors a relying party can pin, without any private material."""
        service_ = current_service()
        return jsonify(
            {
                "roots": [
                    {
                        "root_id": root["root_id"],
                        "name": root["name"],
                        "key_id": root["key_id"],
                        "public_key": root["public_jwk"],
                        "capabilities": root["capabilities"],
                        "is_default": root["is_default"],
                        "certificate": service_.store.get_certificate(root["cert_id"]),
                    }
                    for root in service_.store.list_roots()
                ]
            }
        )

    # -- trust roots --------------------------------------------------------

    @app.post("/trust/roots")
    def create_root():
        payload = body()
        root, certificate = current_service().bootstrap_root(
            name=payload.get("name"),
            capabilities=payload.get("capabilities"),
            ttl_seconds=payload.get("ttl_seconds"),
            make_default=payload.get("make_default"),
            metadata=payload.get("metadata"),
        )
        return (
            jsonify(
                {
                    "root_id": root["root_id"],
                    "name": root["name"],
                    "key_id": root["key_id"],
                    "public_key": root["public_jwk"],
                    "capabilities": root["capabilities"],
                    "is_default": root["is_default"],
                    "certificate": certificate,
                    "created_at": root["created_at"],
                }
            ),
            201,
        )

    @app.get("/trust/roots")
    def list_roots():
        service_ = current_service()
        return jsonify(
            {
                "roots": [
                    {
                        "root_id": root["root_id"],
                        "name": root["name"],
                        "key_id": root["key_id"],
                        "capabilities": root["capabilities"],
                        "is_default": root["is_default"],
                        "has_private_key": bool(root["sealed_private_key"]),
                        "created_at": root["created_at"],
                    }
                    for root in service_.store.list_roots()
                ]
            }
        )

    @app.post("/trust/roots/<root_id>/default")
    def make_root_default(root_id):
        root = current_service().store.set_default_root(root_id)
        return jsonify({"root_id": root["root_id"], "is_default": True})

    # -- minting ------------------------------------------------------------

    @app.post("/agents/mint")
    def mint_agent():
        result = current_service().mint_agent(body(), actor=actor())
        return jsonify(result.to_dict()), result.status_code

    @app.post("/agents/register")
    def register_agent():
        """ACP v2 compatible registration.

        Same request fields, status codes and conflict codes as
        ``iac-bus/docs/ACP_PROTOCOL_V2.md`` section 4.1, with the minted key and
        certificate returned under a ``keychain`` key that ACP v2 clients ignore.
        """
        result = current_service().mint_agent(
            body(), require_medium=True, actor=actor()
        )
        return jsonify(result.to_acp_register_response()), result.status_code

    @app.post("/agents/heartbeat")
    def heartbeat():
        payload = body()
        endpoint = current_service().heartbeat(
            payload.get("agent_uuid") or "",
            payload.get("medium") or "api",
            payload.get("session_id"),
        )
        return jsonify({"success": True, "last_seen_at": endpoint["last_seen_at"]})

    @app.get("/agents")
    def list_agents():
        limit = min(int(request.args.get("limit", 100)), 500)
        agents = current_service().store.list_agents(
            brand=request.args.get("brand"),
            repo_locale=request.args.get("repo_locale"),
            role=request.args.get("role"),
            status=request.args.get("status"),
            parent_agent_uuid=request.args.get("parent_agent_uuid"),
            limit=limit,
            offset=int(request.args.get("offset", 0)),
        )
        return jsonify(
            {
                "agents": [
                    {
                        "agent_uuid": agent["agent_uuid"],
                        "logical_handle": agent["logical_handle"],
                        "role": agent["role"],
                        "status": agent["status"],
                        "parent_agent_uuid": agent["parent_agent_uuid"],
                        "key_id": agent["key_id"],
                        "capabilities": agent["capabilities"],
                        "created_at": agent["created_at"],
                    }
                    for agent in agents
                ],
                "count": len(agents),
            }
        )

    @app.get("/agents/<reference>/chain")
    def agent_chain(reference):
        service_ = current_service()
        agent = service_.require_agent(reference)
        return jsonify(
            {
                "logical_handle": agent["logical_handle"],
                "certificate_chain": service_.store.get_certificate_chain(
                    agent["cert_id"]
                ),
            }
        )

    @app.post("/agents/<reference>/revoke")
    def revoke_agent(reference):
        payload = request.get_json(silent=True) or {}
        return jsonify(
            current_service().revoke_agent(
                reference,
                reason=payload.get("reason"),
                cascade=payload.get("cascade", True),
                actor=actor(),
            )
        )

    @app.get("/agents/<reference>")
    def get_agent(reference):
        include_chain = request.args.get("chain", "1") not in {"0", "false", "no"}
        return jsonify(
            current_service().describe_agent(reference, include_chain=include_chain)
        )

    # -- verification -------------------------------------------------------

    @app.post("/verify/certificate")
    def verify_certificate():
        payload = body()
        service_ = current_service()
        check_revocation = payload.get("check_revocation", True)
        if payload.get("certificate_chain"):
            result = service_.verify_chain(
                payload["certificate_chain"], check_revocation=check_revocation
            )
        elif payload.get("certificate"):
            result = service_.verify_certificate(
                payload["certificate"], check_revocation=check_revocation
            )
        else:
            raise ValidationError("provide either certificate or certificate_chain")
        return jsonify(result.to_dict())

    @app.get("/revocations")
    def revocations():
        service_ = current_service()
        return jsonify(
            {
                "revocations": service_.store.list_revocations(
                    since=request.args.get("since"),
                    limit=min(int(request.args.get("limit", 500)), 1000),
                )
            }
        )

    @app.get("/audit")
    def audit():
        return jsonify(
            {
                "audit": current_service().store.list_audit(
                    logical_handle=request.args.get("logical_handle"),
                    limit=min(int(request.args.get("limit", 100)), 500),
                )
            }
        )

    # -- tokens -------------------------------------------------------------

    @app.post("/tokens/issue")
    def issue_token():
        payload = body()
        reference = payload.get("agent_uuid") or payload.get("logical_handle")
        if not reference:
            raise ValidationError("agent_uuid or logical_handle is required")
        return jsonify(
            current_service().issue_token(
                reference,
                audience=payload.get("audience"),
                ttl_seconds=payload.get("ttl_seconds"),
                capabilities=payload.get("capabilities"),
                self_contained=payload.get("self_contained"),
                actor=actor(),
            )
        )

    @app.post("/tokens/verify")
    def verify_token():
        payload = body()
        token = payload.get("token")
        if not token:
            raise ValidationError("token is required")
        result = current_service().verify_token(
            token,
            audience=payload.get("audience"),
            required_capabilities=payload.get("required_capabilities"),
            check_revocation=payload.get("check_revocation", True),
        )
        return jsonify(result.to_dict()), 200 if result.valid else 403

    return app


def main():
    config = KeyChainConfig.from_env()
    app = create_app(config=config)
    app.run(
        host=os.environ.get("KEYCHAIN_HOST", "0.0.0.0"),
        port=config.port,
        debug=os.environ.get("KEYCHAIN_DEBUG", "").strip().lower()
        in {"1", "true", "yes", "on"},
        threaded=True,
    )


if __name__ == "__main__":
    main()
