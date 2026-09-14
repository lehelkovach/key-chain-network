"""Agent identity grammar, compatible with the IAC-Bus ACP v2 identity model.

ACP v2 (`iac-bus/docs/ACP_PROTOCOL_V2.md` section 2) defines three layers:

* canonical identity  -- ``agent_uuid``, immutable and authoritative
* logical handle      -- ``agent:<brand>.<repo-locale>.<ordinal-path>``
* endpoint handle     -- ``<logical-handle>@<medium>``

KeyChain is the minting authority for those values. This module owns the grammar
and nothing else: no storage, no crypto, no I/O. Keeping it dependency-free
means the same rules can be vendored into clients that only need to validate a
handle.
"""

import re
import uuid

from .errors import ValidationError

LOGICAL_HANDLE_PREFIX = "agent:"

ORDINAL_PATH_RE = re.compile(r"^([0-9]+)(-[0-9]+)*$")
BRAND_RE = re.compile(r"^[a-z0-9_-]+$")
REPO_LOCALE_RE = re.compile(r"^[a-z0-9_.-]+$")
ROLE_RE = re.compile(r"^[a-z0-9_-]+$")
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
LOGICAL_HANDLE_RE = re.compile(
    r"^agent:[a-z0-9_-]+\.[a-z0-9_.-]+\.[0-9]+(-[0-9]+)*$"
)

#: Media recognised by ACP v2 `/agents/register`.
MEDIA = ("web", "slack", "ide", "api", "automation", "other")

#: Roles KeyChain knows about. Any lowercase slug is accepted so downstream
#: projects can add their own, but these are the ones with defined authority in
#: the ACP v2 authority model.
KNOWN_ROLES = ("orchestrator", "master", "worker", "reviewer", "observer", "service")

#: Ordinal of the master/root agent in a repo namespace.
MASTER_ORDINAL = "0"

#: Deepest ordinal path KeyChain will mint, counting the master as depth 1.
MAX_ORDINAL_DEPTH = 12

#: Namespace for deriving stable UUIDv5 agent identifiers. Random UUIDv4 is the
#: default; derived UUIDs let two KeyChain instances under the same trust root
#: agree on an agent_uuid for the same handle without coordinating.
UUID_NAMESPACE = uuid.UUID("6f0f2b8a-2f6a-5c4e-9b1d-8a3c5f9e1d70")

UUID_MODE_RANDOM = "random"
UUID_MODE_DERIVED = "derived"
UUID_MODES = (UUID_MODE_RANDOM, UUID_MODE_DERIVED)


def normalize_slug(value, field):
    """Trim and lowercase a slug field, as required by ACP v2 normalization."""
    if not isinstance(value, str):
        raise ValidationError("%s must be a string" % field)
    normalized = value.strip().lower()
    if not normalized:
        raise ValidationError("%s must not be empty" % field)
    return normalized


def normalize_brand(value):
    brand = normalize_slug(value, "brand")
    if not BRAND_RE.match(brand):
        raise ValidationError("brand must match %s" % BRAND_RE.pattern)
    return brand


def normalize_repo_locale(value):
    repo_locale = normalize_slug(value, "repo_locale")
    if not REPO_LOCALE_RE.match(repo_locale):
        raise ValidationError("repo_locale must match %s" % REPO_LOCALE_RE.pattern)
    if repo_locale.startswith(".") or repo_locale.endswith("."):
        raise ValidationError("repo_locale must not start or end with '.'")
    return repo_locale


def normalize_role(value):
    role = normalize_slug(value, "role")
    if not ROLE_RE.match(role):
        raise ValidationError("role must match %s" % ROLE_RE.pattern)
    return role


def normalize_medium(value):
    medium = normalize_slug(value, "medium")
    if medium not in MEDIA:
        raise ValidationError("medium must be one of %s" % ", ".join(MEDIA))
    return medium


def normalize_session_id(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("session_id must be a string")
    session_id = value.strip()
    if not session_id:
        return None
    if not SESSION_ID_RE.match(session_id):
        raise ValidationError("session_id must match %s" % SESSION_ID_RE.pattern)
    return session_id


def validate_ordinal_path(value):
    """Validate an ordinal path and return it unchanged.

    ACP v2 requires the shape to be preserved after validation, so this only
    strips surrounding whitespace.
    """
    if not isinstance(value, str):
        raise ValidationError("ordinal_path must be a string")
    ordinal_path = value.strip()
    if not ORDINAL_PATH_RE.match(ordinal_path):
        raise ValidationError(
            "ordinal_path must match %s" % ORDINAL_PATH_RE.pattern
        )
    segments = ordinal_path.split("-")
    for segment in segments:
        if len(segment) > 1 and segment.startswith("0"):
            raise ValidationError(
                "ordinal_path segments must not have leading zeros: %s" % ordinal_path
            )
    if len(segments) > MAX_ORDINAL_DEPTH:
        raise ValidationError(
            "ordinal_path depth %d exceeds maximum %d"
            % (len(segments), MAX_ORDINAL_DEPTH)
        )
    return ordinal_path


def parse_ordinal_path(value):
    """Return an ordinal path as a tuple of integers."""
    return tuple(int(segment) for segment in validate_ordinal_path(value).split("-"))


def format_ordinal_path(segments):
    if not segments:
        raise ValidationError("ordinal_path must have at least one segment")
    return "-".join(str(int(segment)) for segment in segments)


def ordinal_depth(value):
    return len(parse_ordinal_path(value))


def parent_ordinal_path(value):
    """Ordinal path of the parent, or ``None`` for a master agent."""
    segments = parse_ordinal_path(value)
    if len(segments) == 1:
        return None
    return format_ordinal_path(segments[:-1])


def child_ordinal_path(parent, child_index):
    """Build ``<parent>-<child_index>``."""
    if not isinstance(child_index, int) or isinstance(child_index, bool):
        raise ValidationError("child_index must be an integer")
    if child_index < 0:
        raise ValidationError("child_index must not be negative")
    return validate_ordinal_path(
        "%s-%d" % (validate_ordinal_path(parent), child_index)
    )


def is_direct_child_ordinal(parent, child):
    """True when ``child`` is exactly one level below ``parent``."""
    parent_segments = parse_ordinal_path(parent)
    child_segments = parse_ordinal_path(child)
    return (
        len(child_segments) == len(parent_segments) + 1
        and child_segments[: len(parent_segments)] == parent_segments
    )


def is_descendant_ordinal(ancestor, candidate):
    ancestor_segments = parse_ordinal_path(ancestor)
    candidate_segments = parse_ordinal_path(candidate)
    return (
        len(candidate_segments) > len(ancestor_segments)
        and candidate_segments[: len(ancestor_segments)] == ancestor_segments
    )


def build_logical_handle(brand, repo_locale, ordinal_path):
    """``agent:<brand>.<repo-locale>.<ordinal-path>``."""
    return "%s%s.%s.%s" % (
        LOGICAL_HANDLE_PREFIX,
        normalize_brand(brand),
        normalize_repo_locale(repo_locale),
        validate_ordinal_path(ordinal_path),
    )


def build_endpoint_handle(logical_handle, medium):
    """``<logical-handle>@<medium>``."""
    return "%s@%s" % (
        validate_logical_handle(logical_handle),
        normalize_medium(medium),
    )


def validate_logical_handle(value):
    if not isinstance(value, str):
        raise ValidationError("logical_handle must be a string")
    handle = value.strip()
    if not LOGICAL_HANDLE_RE.match(handle):
        raise ValidationError(
            "logical_handle must match %s" % LOGICAL_HANDLE_RE.pattern
        )
    return handle


def parse_logical_handle(value):
    """Split a logical handle into ``(brand, repo_locale, ordinal_path)``.

    ``repo_locale`` may itself contain dots, so the brand is taken from the
    first separator and the ordinal path from the last. That is unambiguous
    because ordinal paths never contain a dot.
    """
    handle = validate_logical_handle(value)
    body = handle[len(LOGICAL_HANDLE_PREFIX) :]
    brand, _, remainder = body.partition(".")
    repo_locale, _, ordinal_path = remainder.rpartition(".")
    return (
        normalize_brand(brand),
        normalize_repo_locale(repo_locale),
        validate_ordinal_path(ordinal_path),
    )


def parse_endpoint_handle(value):
    """Split an endpoint handle into ``(logical_handle, medium)``."""
    if not isinstance(value, str):
        raise ValidationError("endpoint_handle must be a string")
    handle = value.strip()
    logical_handle, separator, medium = handle.rpartition("@")
    if not separator:
        raise ValidationError("endpoint_handle must be <logical-handle>@<medium>")
    return validate_logical_handle(logical_handle), normalize_medium(medium)


def same_namespace(first_handle, second_handle):
    """True when two logical handles share a ``(brand, repo_locale)`` namespace."""
    first = parse_logical_handle(first_handle)
    second = parse_logical_handle(second_handle)
    return first[:2] == second[:2]


def mint_agent_uuid(logical_handle, mode=UUID_MODE_RANDOM, namespace_seed=None):
    """Allocate the canonical ``agent_uuid`` for a logical handle.

    ``random`` yields UUIDv4 as ACP v2 specifies. ``derived`` yields a UUIDv5
    over ``<namespace_seed>|<logical_handle>``, which makes minting reproducible
    across KeyChain replicas that share a trust root.
    """
    if mode == UUID_MODE_RANDOM:
        return str(uuid.uuid4())
    if mode == UUID_MODE_DERIVED:
        if not namespace_seed:
            raise ValidationError("derived uuid mode requires a namespace_seed")
        name = "%s|%s" % (namespace_seed, validate_logical_handle(logical_handle))
        return str(uuid.uuid5(UUID_NAMESPACE, name))
    raise ValidationError("uuid mode must be one of %s" % ", ".join(UUID_MODES))


def validate_agent_uuid(value):
    if not isinstance(value, str):
        raise ValidationError("agent_uuid must be a string")
    try:
        parsed = uuid.UUID(value.strip())
    except (ValueError, AttributeError) as exc:
        raise ValidationError("agent_uuid must be a UUID") from exc
    return str(parsed)
