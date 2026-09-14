"""Capability grammar and role defaults.

A capability is a dot-separated lowercase path such as ``bus.post``. A grant may
end in ``*`` to cover a subtree (``bus.*``), and the bare ``*`` grants
everything. Trust roots hold ``*``; every mint below a root may only narrow what
its issuer already holds, which is what makes a KeyChain certificate chain
safe to evaluate bottom-up: the leaf's capability set is always an upper bound on
what the agent can do, no matter which link you inspect.
"""

import re

from .errors import ValidationError

WILDCARD = "*"
CAPABILITY_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?$")

#: Capabilities KeyChain mints by default for each known role. Chosen to line up
#: with the IAC-Bus surface (post/read/claim/ack) plus the coordination verbs in
#: the ACP v2 authority model.
ROLE_CAPABILITIES = {
    "orchestrator": (
        "agent.mint",
        "bus.ack",
        "bus.claim",
        "bus.post",
        "bus.read",
        "lock.acquire",
        "task.assign",
    ),
    "master": (
        "agent.mint",
        "bus.ack",
        "bus.claim",
        "bus.post",
        "bus.read",
        "lock.acquire",
        "task.assign",
    ),
    "worker": ("bus.ack", "bus.claim", "bus.post", "bus.read", "lock.acquire"),
    "reviewer": ("bus.post", "bus.read", "task.review"),
    "observer": ("bus.read",),
    "service": ("bus.post", "bus.read"),
}

DEFAULT_CAPABILITIES = ("bus.post", "bus.read")

ROOT_CAPABILITIES = (WILDCARD,)


def normalize_capability(value):
    if not isinstance(value, str):
        raise ValidationError("capability must be a string")
    capability = value.strip().lower()
    if capability == WILDCARD:
        return WILDCARD
    if not CAPABILITY_RE.match(capability):
        raise ValidationError(
            "capability '%s' must match %s or be '*'" % (value, CAPABILITY_RE.pattern)
        )
    return capability


def normalize_capabilities(values):
    """Normalize, de-duplicate and sort a capability list."""
    if values is None:
        return []
    if isinstance(values, str):
        raise ValidationError("capabilities must be a list of strings")
    normalized = {normalize_capability(value) for value in values}
    if WILDCARD in normalized:
        return [WILDCARD]
    return sorted(normalized)


def default_capabilities_for_role(role):
    return list(ROLE_CAPABILITIES.get(role, DEFAULT_CAPABILITIES))


def grant_covers(grant, capability):
    """True when a single grant authorizes ``capability``."""
    if grant == WILDCARD:
        return True
    if grant == capability:
        return True
    if grant.endswith(".*"):
        return capability.startswith(grant[:-1]) or capability == grant[:-2]
    return False


def allows(granted, capability):
    """True when any grant in ``granted`` authorizes ``capability``."""
    capability = normalize_capability(capability)
    return any(grant_covers(grant, capability) for grant in granted)


def is_attenuation(child, parent):
    """True when every capability in ``child`` is already covered by ``parent``."""
    return all(
        any(grant_covers(grant, capability) for grant in parent) for capability in child
    )


def attenuate(requested, available):
    """Narrow ``requested`` to what ``available`` actually covers.

    Raises when the caller asks for something the issuer cannot delegate, rather
    than silently dropping it: a token that quietly lost a capability is much
    harder to debug than a rejected mint.
    """
    requested = normalize_capabilities(requested)
    available = normalize_capabilities(available)
    if requested == [WILDCARD] and available != [WILDCARD]:
        raise ValidationError("issuer cannot delegate the '*' capability")
    excess = [
        capability
        for capability in requested
        if not any(grant_covers(grant, capability) for grant in available)
    ]
    if excess:
        raise ValidationError(
            "issuer cannot delegate capabilities: %s" % ", ".join(sorted(excess)),
            details=["issuer holds: %s" % ", ".join(available)],
        )
    return requested
