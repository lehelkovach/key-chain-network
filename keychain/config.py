"""Runtime configuration, read from the environment.

Every knob has a default that produces a working local instance except
``KEYCHAIN_MASTER_KEY``: holding trust-root private keys unsealed is a decision
an operator has to make explicitly (see :func:`keychain.keys.key_wrapper_from_env`).
"""

import os

from . import identity
from .errors import ConfigurationError

DEFAULT_DB_PATH = "keychain.db"
DEFAULT_PORT = 8102
DEFAULT_ROOT_NAME = "local-dev-root"
DEFAULT_TOKEN_TTL_SECONDS = 3600
DEFAULT_MAX_TOKEN_TTL_SECONDS = 7 * 24 * 3600
DEFAULT_AGENT_CERT_TTL_SECONDS = 90 * 24 * 3600
DEFAULT_ROOT_CERT_TTL_SECONDS = 5 * 365 * 24 * 3600

ISSUER_AUTO = "auto"
ISSUER_ROOT = "root"
ISSUER_PARENT = "parent"
ISSUER_MODES = (ISSUER_AUTO, ISSUER_ROOT, ISSUER_PARENT)


def _bool(env, name, default=False):
    raw = env.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _int(env, name, default):
    raw = env.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(str(raw).strip())
    except ValueError as exc:
        raise ConfigurationError("%s must be an integer" % name) from exc


def _optional_int(env, name):
    raw = env.get(name)
    if raw is None or str(raw).strip() == "":
        return None
    return _int(env, name, 0)


class KeyChainConfig:
    """Resolved configuration for a KeyChain instance."""

    def __init__(
        self,
        db_path=DEFAULT_DB_PATH,
        api_token="",
        port=DEFAULT_PORT,
        uuid_mode=identity.UUID_MODE_RANDOM,
        default_audience=("iac-bus",),
        token_ttl_seconds=DEFAULT_TOKEN_TTL_SECONDS,
        max_token_ttl_seconds=DEFAULT_MAX_TOKEN_TTL_SECONDS,
        agent_cert_ttl_seconds=DEFAULT_AGENT_CERT_TTL_SECONDS,
        root_cert_ttl_seconds=DEFAULT_ROOT_CERT_TTL_SECONDS,
        auto_bootstrap_root=False,
        default_root_name=DEFAULT_ROOT_NAME,
        issuer_mode=ISSUER_AUTO,
        log_level="INFO",
    ):
        if uuid_mode not in identity.UUID_MODES:
            raise ConfigurationError(
                "uuid mode must be one of %s" % ", ".join(identity.UUID_MODES)
            )
        if issuer_mode not in ISSUER_MODES:
            raise ConfigurationError(
                "issuer mode must be one of %s" % ", ".join(ISSUER_MODES)
            )
        self.db_path = db_path
        self.api_token = api_token
        self.port = port
        self.uuid_mode = uuid_mode
        self.default_audience = tuple(default_audience or ())
        self.token_ttl_seconds = token_ttl_seconds
        self.max_token_ttl_seconds = max_token_ttl_seconds
        self.agent_cert_ttl_seconds = agent_cert_ttl_seconds
        self.root_cert_ttl_seconds = root_cert_ttl_seconds
        self.auto_bootstrap_root = auto_bootstrap_root
        self.default_root_name = default_root_name
        self.issuer_mode = issuer_mode
        self.log_level = log_level

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        audience = env.get("KEYCHAIN_DEFAULT_AUDIENCE", "iac-bus")
        return cls(
            db_path=env.get("KEYCHAIN_DB_PATH", DEFAULT_DB_PATH),
            api_token=env.get("KEYCHAIN_API_TOKEN", ""),
            port=_int(env, "KEYCHAIN_PORT", DEFAULT_PORT),
            uuid_mode=env.get("KEYCHAIN_UUID_MODE", identity.UUID_MODE_RANDOM).strip()
            or identity.UUID_MODE_RANDOM,
            default_audience=tuple(
                entry.strip() for entry in audience.split(",") if entry.strip()
            ),
            token_ttl_seconds=_int(
                env, "KEYCHAIN_TOKEN_TTL_SECONDS", DEFAULT_TOKEN_TTL_SECONDS
            ),
            max_token_ttl_seconds=_int(
                env, "KEYCHAIN_MAX_TOKEN_TTL_SECONDS", DEFAULT_MAX_TOKEN_TTL_SECONDS
            ),
            agent_cert_ttl_seconds=_optional_int(env, "KEYCHAIN_AGENT_CERT_TTL_SECONDS")
            if env.get("KEYCHAIN_AGENT_CERT_TTL_SECONDS")
            else DEFAULT_AGENT_CERT_TTL_SECONDS,
            root_cert_ttl_seconds=_int(
                env, "KEYCHAIN_ROOT_CERT_TTL_SECONDS", DEFAULT_ROOT_CERT_TTL_SECONDS
            ),
            auto_bootstrap_root=_bool(env, "KEYCHAIN_AUTO_BOOTSTRAP_ROOT", False),
            default_root_name=env.get("KEYCHAIN_ROOT_NAME", DEFAULT_ROOT_NAME),
            issuer_mode=env.get("KEYCHAIN_ISSUER_MODE", ISSUER_AUTO).strip()
            or ISSUER_AUTO,
            log_level=env.get("KEYCHAIN_LOG_LEVEL", "INFO").upper(),
        )

    def to_dict(self):
        """Non-secret view of the configuration, safe to expose on ``/health``."""
        return {
            "db_path": self.db_path,
            "port": self.port,
            "uuid_mode": self.uuid_mode,
            "default_audience": list(self.default_audience),
            "token_ttl_seconds": self.token_ttl_seconds,
            "max_token_ttl_seconds": self.max_token_ttl_seconds,
            "agent_cert_ttl_seconds": self.agent_cert_ttl_seconds,
            "root_cert_ttl_seconds": self.root_cert_ttl_seconds,
            "auto_bootstrap_root": self.auto_bootstrap_root,
            "issuer_mode": self.issuer_mode,
            "auth_required": bool(self.api_token),
        }
