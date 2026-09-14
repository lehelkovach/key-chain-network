#!/usr/bin/env python3
"""Command line interface to a local KeyChain store.

Operates directly on the SQLite database rather than over HTTP, so it works for
bootstrap (there is no root to authenticate against yet) and for offline
verification. Every command prints JSON on stdout.

    python3 keychain_cli.py init-root --name lehel-root
    python3 keychain_cli.py mint --brand cursor --repo iac-bus --role orchestrator
    python3 keychain_cli.py mint --brand cursor --repo iac-bus --role worker \\
        --parent agent:cursor.iac-bus.0
    python3 keychain_cli.py verify-token --token "$KC_TOKEN" --audience iac-bus
"""

import argparse
import json
import sys

from keychain import capabilities as caps
from keychain import certificates, keys, tokens
from keychain.config import KeyChainConfig
from keychain.errors import KeyChainError
from keychain.service import KeyChainService
from keychain.store import KeyChainStore
from version import VERSION


def _emit(payload, stream=None):
    json.dump(payload, stream or sys.stdout, indent=2, sort_keys=True)
    (stream or sys.stdout).write("\n")


def _load_json_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _build_service(args):
    config = KeyChainConfig.from_env()
    if args.db:
        config.db_path = args.db
    return KeyChainService(store=KeyChainStore(config.db_path), config=config)


def _split_capabilities(value):
    if not value:
        return None
    return caps.normalize_capabilities(
        [entry.strip() for entry in value.split(",") if entry.strip()]
    )


def cmd_gen_master_key(_args):
    _emit(
        {
            "KEYCHAIN_MASTER_KEY": keys.generate_master_key(),
            "note": "Export this before starting KeyChain. Losing it makes every "
            "private key KeyChain holds unrecoverable.",
        }
    )
    return 0


def cmd_init_root(args):
    service = _build_service(args)
    root, certificate = service.bootstrap_root(
        name=args.name, make_default=not args.no_default
    )
    _emit(
        {
            "root_id": root["root_id"],
            "name": root["name"],
            "key_id": root["key_id"],
            "public_key": root["public_jwk"],
            "is_default": root["is_default"],
            "certificate": certificate,
        }
    )
    return 0


def cmd_roots(args):
    service = _build_service(args)
    _emit(
        {
            "roots": [
                {
                    "root_id": root["root_id"],
                    "name": root["name"],
                    "key_id": root["key_id"],
                    "is_default": root["is_default"],
                    "capabilities": root["capabilities"],
                }
                for root in service.store.list_roots()
            ]
        }
    )
    return 0


def cmd_mint(args):
    service = _build_service(args)
    payload = {
        "brand": args.brand,
        "repo_locale": args.repo,
        "role": args.role,
        "medium": args.medium,
        "custody": args.custody,
        "session_id": args.session_id,
    }
    if args.ordinal:
        payload["ordinal_path"] = args.ordinal
    if args.parent:
        if args.parent.startswith("agent:"):
            payload["parent_handle"] = args.parent
        else:
            payload["parent_agent_uuid"] = args.parent
    capabilities = _split_capabilities(args.capabilities)
    if capabilities is not None:
        payload["capabilities"] = capabilities
    if args.public_key:
        payload["public_key"] = _load_json_file(args.public_key)
    if args.ttl_seconds:
        payload["ttl_seconds"] = args.ttl_seconds

    result = service.mint_agent(payload, actor="cli")
    document = result.to_dict()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            _emit(document, handle)
        summary = {
            key: document[key]
            for key in ("created", "agent_uuid", "logical_handle", "key_id")
        }
        summary["written_to"] = args.out
        summary["contains_private_key"] = "private_key" in document
        _emit(summary)
    else:
        _emit(document)
    return 0


def cmd_show(args):
    service = _build_service(args)
    _emit(service.describe_agent(args.reference, include_chain=not args.no_chain))
    return 0


def cmd_list(args):
    service = _build_service(args)
    _emit(
        {
            "agents": [
                {
                    "agent_uuid": agent["agent_uuid"],
                    "logical_handle": agent["logical_handle"],
                    "role": agent["role"],
                    "status": agent["status"],
                    "key_id": agent["key_id"],
                }
                for agent in service.store.list_agents(
                    brand=args.brand, repo_locale=args.repo, limit=args.limit
                )
            ]
        }
    )
    return 0


def cmd_revoke(args):
    service = _build_service(args)
    _emit(
        service.revoke_agent(
            args.reference,
            reason=args.reason,
            cascade=not args.no_cascade,
            actor="cli",
        )
    )
    return 0


def cmd_token(args):
    """Issue a capability token, signing locally when a private key is supplied."""
    audience = [entry.strip() for entry in (args.audience or "").split(",") if entry.strip()]
    capabilities = _split_capabilities(args.capabilities)

    if args.private_key:
        identity_document = _load_json_file(args.private_key)
        chain = (
            _load_json_file(args.chain)
            if args.chain
            else identity_document.get("certificate_chain")
        )
        private_jwk = identity_document.get("private_key", identity_document)
        if not chain:
            raise KeyChainError(
                "a certificate chain is required; pass --chain or use the mint "
                "document that contains certificate_chain"
            )
        leaf = chain[0]
        subject = dict(leaf.get("subject") or {})
        token = tokens.issue_token(
            keys.load_private_jwk(private_jwk),
            subject,
            capabilities or leaf.get("capabilities") or [],
            audience=audience or None,
            ttl_seconds=args.ttl_seconds,
            chain=chain,
            issuer_ref=subject.get("logical_handle"),
            root_key_id=(chain[-1].get("subject") or {}).get("key_id"),
        )
        _emit(
            {
                "token": token,
                "token_type": "Bearer",
                "expires_in": args.ttl_seconds,
                "logical_handle": subject.get("logical_handle"),
                "self_contained": True,
                "signed_locally": True,
            }
        )
        return 0

    service = _build_service(args)
    _emit(
        service.issue_token(
            args.reference,
            audience=audience or None,
            ttl_seconds=args.ttl_seconds,
            capabilities=capabilities,
            actor="cli",
        )
    )
    return 0


def cmd_verify_token(args):
    """Verify a token, offline against pinned roots or online against the store."""
    audience = [entry.strip() for entry in (args.audience or "").split(",") if entry.strip()]
    required = _split_capabilities(args.require_capabilities)

    if args.trusted_root_key_id:
        result = tokens.verify_token(
            args.token,
            trusted_root_key_ids=[
                entry.strip()
                for entry in args.trusted_root_key_id.split(",")
                if entry.strip()
            ],
            audience=audience or None,
            required_capabilities=required,
        )
    else:
        service = _build_service(args)
        result = service.verify_token(
            args.token,
            audience=audience or None,
            required_capabilities=required,
        )
    _emit(result.to_dict())
    return 0 if result.valid else 1


def cmd_verify_chain(args):
    chain = _load_json_file(args.chain)
    if isinstance(chain, dict):
        chain = chain.get("certificate_chain") or [chain]
    if args.trusted_root_key_id:
        result = certificates.verify_chain(
            chain,
            [
                entry.strip()
                for entry in args.trusted_root_key_id.split(",")
                if entry.strip()
            ],
        )
    else:
        result = _build_service(args).verify_chain(chain)
    _emit(result.to_dict())
    return 0 if result.valid else 1


def cmd_jwks(args):
    _emit(_build_service(args).jwks())
    return 0


def cmd_audit(args):
    service = _build_service(args)
    _emit({"audit": service.store.list_audit(limit=args.limit)})
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="keychain",
        description="Mint and verify agent identities for the IAC-Bus project.",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument(
        "--db",
        help="SQLite database path (default: KEYCHAIN_DB_PATH or keychain.db)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "gen-master-key", help="print a fresh KEYCHAIN_MASTER_KEY"
    ).set_defaults(handler=cmd_gen_master_key)

    init_root = subparsers.add_parser("init-root", help="create a trust root")
    init_root.add_argument("--name", help="root name (default: KEYCHAIN_ROOT_NAME)")
    init_root.add_argument(
        "--no-default", action="store_true", help="do not make this the default root"
    )
    init_root.set_defaults(handler=cmd_init_root)

    subparsers.add_parser("roots", help="list trust roots").set_defaults(
        handler=cmd_roots
    )

    mint = subparsers.add_parser("mint", help="mint an agent identity")
    mint.add_argument("--brand", required=True, help="for example: cursor")
    mint.add_argument("--repo", required=True, help="repo locale, for example: iac-bus")
    mint.add_argument("--role", default="worker")
    mint.add_argument("--medium", default="api", help="web, slack, ide, api, automation, other")
    mint.add_argument("--ordinal", help="explicit ordinal path (default: allocated)")
    mint.add_argument("--parent", help="parent agent_uuid or logical handle")
    mint.add_argument("--session-id", dest="session_id")
    mint.add_argument("--capabilities", help="comma-separated capability list")
    mint.add_argument("--custody", default="agent", choices=("agent", "keychain"))
    mint.add_argument("--public-key", help="path to a JWK the agent generated itself")
    mint.add_argument("--ttl-seconds", type=int, dest="ttl_seconds")
    mint.add_argument("--out", help="write the full mint document to this path")
    mint.set_defaults(handler=cmd_mint)

    show = subparsers.add_parser("show", help="describe an agent")
    show.add_argument("reference", help="agent_uuid, logical handle or endpoint handle")
    show.add_argument("--no-chain", action="store_true")
    show.set_defaults(handler=cmd_show)

    list_agents = subparsers.add_parser("list", help="list agents")
    list_agents.add_argument("--brand")
    list_agents.add_argument("--repo", dest="repo")
    list_agents.add_argument("--limit", type=int, default=100)
    list_agents.set_defaults(handler=cmd_list)

    revoke = subparsers.add_parser("revoke", help="revoke an agent and its subtree")
    revoke.add_argument("reference")
    revoke.add_argument("--reason")
    revoke.add_argument("--no-cascade", action="store_true")
    revoke.set_defaults(handler=cmd_revoke)

    token = subparsers.add_parser("token", help="issue a capability token")
    token.add_argument("reference", nargs="?", help="agent_uuid or logical handle")
    token.add_argument("--audience", default="iac-bus")
    token.add_argument("--ttl-seconds", type=int, default=3600, dest="ttl_seconds")
    token.add_argument("--capabilities")
    token.add_argument(
        "--private-key",
        help="mint document or JWK to sign with locally, without touching the store",
    )
    token.add_argument("--chain", help="certificate chain JSON for local signing")
    token.set_defaults(handler=cmd_token)

    verify_token = subparsers.add_parser("verify-token", help="verify a token")
    verify_token.add_argument("--token", required=True)
    verify_token.add_argument("--audience")
    verify_token.add_argument("--require-capabilities", dest="require_capabilities")
    verify_token.add_argument(
        "--trusted-root-key-id",
        help="verify offline against these root key ids instead of the local store",
    )
    verify_token.set_defaults(handler=cmd_verify_token)

    verify_chain = subparsers.add_parser(
        "verify-chain", help="verify a certificate chain"
    )
    verify_chain.add_argument("--chain", required=True, help="path to chain JSON")
    verify_chain.add_argument("--trusted-root-key-id")
    verify_chain.set_defaults(handler=cmd_verify_chain)

    subparsers.add_parser("jwks", help="print the trust root JWKS").set_defaults(
        handler=cmd_jwks
    )

    audit = subparsers.add_parser("audit", help="print the mint audit log")
    audit.add_argument("--limit", type=int, default=50)
    audit.set_defaults(handler=cmd_audit)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except KeyChainError as error:
        _emit(error.to_dict(), sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
