"""KeyChain Network: agent identity minting with a verifiable chain of trust.

KeyChain mints agent identities that are wire-compatible with the IAC-Bus ACP v2
identity model (`agent_uuid` + `agent:<brand>.<repo-locale>.<ordinal-path>`) and
binds each identity to an Ed25519 key pair certified by its parent, up to a
human-held trust root.
"""

from version import VERSION, __version__

__all__ = ["VERSION", "__version__"]
