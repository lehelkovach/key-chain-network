"""Single source of truth for the KeyChain service version."""

import os

_VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")


def _read_version():
    try:
        with open(_VERSION_FILE, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError:
        return "0.0.0-unknown"
    return value or "0.0.0-unknown"


VERSION = _read_version()
__version__ = VERSION

# Protocol version advertised in certificates, tokens and API responses. Bumped
# independently of the service version.
PROTOCOL_VERSION = "kc1"
