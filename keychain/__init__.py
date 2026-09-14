"""KeyChain Network: agent identity minting with a verifiable chain of trust.

KeyChain mints agent identities that are wire-compatible with the IAC-Bus ACP v2
identity model (`agent_uuid` + `agent:<brand>.<repo-locale>.<ordinal-path>`) and
binds each identity to an Ed25519 key pair certified by its parent, up to a
human-held trust root.

The package has no dependency on the surrounding repository, so a relying party
can vendor the modules it needs for verification -- ``certificates``, ``tokens``,
``capabilities``, ``identity``, ``keys``, ``canonical``, ``errors``, ``protocol``
-- without taking the service, the store or the CLI.
"""

from .protocol import PROTOCOL_VERSION

__all__ = ["PROTOCOL_VERSION"]
