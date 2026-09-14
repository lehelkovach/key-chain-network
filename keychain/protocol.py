"""Wire protocol version.

Deliberately import-free. ``certificates.py`` and ``tokens.py`` are meant to be
vendorable into a relying party such as IAC-Bus (see
``docs/IAC_BUS_INTEGRATION.md``), so nothing under ``keychain/`` may reach outside
the package for the version it stamps on signed documents.

Bump this only for a breaking format change, and only together with the schemas,
the verification code and ``docs/KEYCHAIN_PROTOCOL.md``. Verifiers reject an
unknown version rather than ignoring unrecognised fields, because a signature
covers every member of a document.
"""

PROTOCOL_VERSION = "kc1"
