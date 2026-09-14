"""Identity certificates and chain-of-trust verification.

A KeyChain certificate binds a minted identity to an Ed25519 public key and is
signed by the identity that issued it. Following ``issuer`` links upward gives a
chain that terminates in a self-signed trust root:

    root (human-held)
      └── agent:cursor.iac-bus.0        (orchestrator)
            └── agent:cursor.iac-bus.0-1  (worker)

Verification is offline: a relying party such as IAC-Bus needs the chain and the
key identifier of a root it trusts, nothing else. The wire format is plain JSON
rather than X.509 so that any client can validate one with a JSON parser and an
Ed25519 verify.
"""

import uuid

from . import capabilities as caps
from . import identity, keys
from .canonical import (
    canonical_json,
    from_iso8601,
    to_iso8601,
    utcnow,
)
from .errors import SignatureError, TrustError, ValidationError
from .protocol import PROTOCOL_VERSION

CERT_TYPE_ROOT = "root"
CERT_TYPE_AGENT = "agent"
CERT_TYPES = (CERT_TYPE_ROOT, CERT_TYPE_AGENT)

#: Longest chain accepted by :func:`verify_chain`, root included.
MAX_CHAIN_DEPTH = 16

#: Tolerance for clock skew between issuer and verifier, in seconds.
CLOCK_SKEW_SECONDS = 60


def _require_object(value, field):
    if not isinstance(value, dict):
        raise ValidationError("%s must be an object" % field)
    return value


def signing_payload(certificate):
    """Canonical bytes covered by a certificate's signature.

    Everything except the ``signature`` member is signed, so an unknown future
    field cannot be added to a certificate without breaking its signature.
    """
    unsigned = {
        key: value for key, value in certificate.items() if key != "signature"
    }
    return canonical_json(unsigned)


def build_root_subject(root_id, name, public_jwk):
    return {
        "root_id": root_id,
        "name": name,
        "key_id": keys.key_id_for_jwk(public_jwk),
        "public_key": public_jwk,
    }


def build_agent_subject(
    agent_uuid,
    logical_handle,
    role,
    public_jwk,
    parent_agent_uuid=None,
):
    brand, repo_locale, ordinal_path = identity.parse_logical_handle(logical_handle)
    subject = {
        "agent_uuid": identity.validate_agent_uuid(agent_uuid),
        "logical_handle": logical_handle,
        "brand": brand,
        "repo_locale": repo_locale,
        "ordinal_path": ordinal_path,
        "role": identity.normalize_role(role),
        "key_id": keys.key_id_for_jwk(public_jwk),
        "public_key": public_jwk,
    }
    if parent_agent_uuid:
        subject["parent_agent_uuid"] = identity.validate_agent_uuid(parent_agent_uuid)
    return subject


def subject_reference(certificate):
    """Human-readable identifier for a certificate's subject."""
    subject = certificate.get("subject") or {}
    if certificate.get("cert_type") == CERT_TYPE_ROOT:
        return "root:%s" % subject.get("root_id")
    return subject.get("logical_handle")


def issue_certificate(
    cert_type,
    subject,
    capabilities,
    signing_key,
    issuer_certificate=None,
    issued_at=None,
    expires_at=None,
    cert_id=None,
):
    """Build and sign a certificate.

    ``issuer_certificate`` is omitted only for a self-signed root. For every
    other certificate the issuer's own certificate is required so the ``issuer``
    block can reference it by ``cert_id`` as well as ``key_id``; that makes chain
    reconstruction unambiguous when one key has signed several certificates.
    """
    _require_object(subject, "subject")
    if cert_type not in CERT_TYPES:
        raise ValidationError("cert_type must be one of %s" % ", ".join(CERT_TYPES))

    issued_at = issued_at or utcnow()
    signer_jwk = keys.public_jwk(signing_key.public_key())
    signer_key_id = keys.key_id_for_jwk(signer_jwk)

    if issuer_certificate is None:
        if cert_type != CERT_TYPE_ROOT:
            raise ValidationError("only root certificates may be self-signed")
        if subject.get("key_id") != signer_key_id:
            raise ValidationError("root certificate must be signed by its own key")
        issuer_block = {
            "cert_id": None,
            "key_id": signer_key_id,
            "subject_ref": "root:%s" % subject.get("root_id"),
            "self_signed": True,
        }
    else:
        _require_object(issuer_certificate, "issuer_certificate")
        issuer_subject = _require_object(
            issuer_certificate.get("subject"), "issuer_certificate.subject"
        )
        if issuer_subject.get("key_id") != signer_key_id:
            raise ValidationError(
                "signing key does not match the issuer certificate subject key"
            )
        issuer_block = {
            "cert_id": issuer_certificate.get("cert_id"),
            "key_id": signer_key_id,
            "subject_ref": subject_reference(issuer_certificate),
            "self_signed": False,
        }
        issuer_expiry = from_iso8601(issuer_certificate.get("expires_at"))
        subject_expiry = expires_at
        if issuer_expiry is not None and (
            subject_expiry is None or subject_expiry > issuer_expiry
        ):
            # A certificate must never outlive its issuer.
            subject_expiry = issuer_expiry
        expires_at = subject_expiry

    certificate = {
        "kc_version": PROTOCOL_VERSION,
        "cert_type": cert_type,
        "cert_id": cert_id or str(uuid.uuid4()),
        "subject": subject,
        "issuer": issuer_block,
        "capabilities": caps.normalize_capabilities(capabilities),
        "issued_at": to_iso8601(issued_at),
        "expires_at": to_iso8601(expires_at),
    }
    certificate["signature"] = {
        "alg": keys.JWS_ALGORITHM,
        "key_id": signer_key_id,
        "value": keys.sign(signing_key, signing_payload(certificate)),
    }
    return certificate


def verify_signature(certificate, issuer_public_jwk):
    """Verify one certificate's signature against its issuer's public key."""
    _require_object(certificate, "certificate")
    signature = _require_object(certificate.get("signature"), "certificate.signature")
    if signature.get("alg") != keys.JWS_ALGORITHM:
        raise ValidationError("unsupported signature alg %r" % signature.get("alg"))
    issuer_key_id = keys.key_id_for_jwk(issuer_public_jwk)
    if signature.get("key_id") != issuer_key_id:
        raise SignatureError(
            "certificate signature key_id does not match the issuer key"
        )
    public_key = keys.load_public_jwk(issuer_public_jwk)
    keys.verify(public_key, signature.get("value") or "", signing_payload(certificate))
    return True


def is_expired(certificate, now=None):
    expires_at = from_iso8601(certificate.get("expires_at"))
    if expires_at is None:
        return False
    now = now or utcnow()
    return now.timestamp() - CLOCK_SKEW_SECONDS > expires_at.timestamp()


def is_not_yet_valid(certificate, now=None):
    issued_at = from_iso8601(certificate.get("issued_at"))
    if issued_at is None:
        return False
    now = now or utcnow()
    return now.timestamp() + CLOCK_SKEW_SECONDS < issued_at.timestamp()


class ChainVerification:
    """Outcome of :func:`verify_chain`."""

    def __init__(self, valid, errors=None, root_key_id=None, subject=None,
                 capabilities=None, chain_length=0):
        self.valid = valid
        self.errors = list(errors or [])
        self.root_key_id = root_key_id
        self.subject = subject
        self.capabilities = list(capabilities or [])
        self.chain_length = chain_length

    def to_dict(self):
        return {
            "valid": self.valid,
            "errors": self.errors,
            "root_key_id": self.root_key_id,
            "subject": self.subject,
            "capabilities": self.capabilities,
            "chain_length": self.chain_length,
        }

    def raise_for_status(self):
        if not self.valid:
            raise TrustError(
                "certificate chain verification failed", details=self.errors
            )
        return self


def _check_link(child, issuer, errors):
    """Structural checks between a certificate and the one that signed it."""
    child_issuer = child.get("issuer") or {}
    issuer_subject = issuer.get("subject") or {}

    if child_issuer.get("key_id") != issuer_subject.get("key_id"):
        errors.append(
            "issuer key_id mismatch: %s declares issuer %s but next certificate "
            "holds %s"
            % (
                subject_reference(child),
                child_issuer.get("key_id"),
                issuer_subject.get("key_id"),
            )
        )
    declared_cert_id = child_issuer.get("cert_id")
    if declared_cert_id is not None and declared_cert_id != issuer.get("cert_id"):
        errors.append(
            "issuer cert_id mismatch for %s" % subject_reference(child)
        )

    child_expiry = from_iso8601(child.get("expires_at"))
    issuer_expiry = from_iso8601(issuer.get("expires_at"))
    if issuer_expiry is not None and (
        child_expiry is None or child_expiry > issuer_expiry
    ):
        errors.append(
            "%s outlives its issuer %s"
            % (subject_reference(child), subject_reference(issuer))
        )

    if not caps.is_attenuation(
        child.get("capabilities") or [], issuer.get("capabilities") or []
    ):
        errors.append(
            "%s claims capabilities its issuer cannot delegate"
            % subject_reference(child)
        )

    if (
        child.get("cert_type") == CERT_TYPE_AGENT
        and issuer.get("cert_type") == CERT_TYPE_AGENT
    ):
        _check_agent_hierarchy(child, issuer, errors)


def _check_agent_hierarchy(child, issuer, errors):
    """Ordinal-path parenting rules for an agent issued by another agent.

    Ordinal paths are only meaningful inside a ``(brand, repo_locale)``
    namespace, so a child in the same namespace must sit exactly one level below
    its issuer. Cross-namespace delegation is allowed without an ordinal
    relationship: an orchestrator in one repo legitimately mints the master agent
    of another repo.
    """
    child_subject = child.get("subject") or {}
    issuer_subject = issuer.get("subject") or {}
    same_namespace = (
        child_subject.get("brand") == issuer_subject.get("brand")
        and child_subject.get("repo_locale") == issuer_subject.get("repo_locale")
    )
    if not same_namespace:
        return
    try:
        direct_child = identity.is_direct_child_ordinal(
            issuer_subject.get("ordinal_path") or "",
            child_subject.get("ordinal_path") or "",
        )
    except ValidationError as exc:
        errors.append("invalid ordinal path in chain: %s" % exc)
        return
    if not direct_child:
        errors.append(
            "ordinal path %s is not a direct child of issuer %s"
            % (
                child_subject.get("ordinal_path"),
                issuer_subject.get("ordinal_path"),
            )
        )
    declared_parent = child_subject.get("parent_agent_uuid")
    if declared_parent and declared_parent != issuer_subject.get("agent_uuid"):
        errors.append(
            "%s declares parent %s but was signed by %s"
            % (
                subject_reference(child),
                declared_parent,
                issuer_subject.get("agent_uuid"),
            )
        )


def verify_chain(chain, trusted_root_key_ids, now=None, is_revoked=None):
    """Verify a leaf-to-root certificate chain.

    ``chain[0]`` is the leaf and ``chain[-1]`` must be a self-signed root whose
    ``key_id`` appears in ``trusted_root_key_ids``. ``is_revoked`` is an optional
    callable taking a certificate and returning True when it has been revoked;
    omit it for purely offline verification.

    All problems are collected instead of raising on the first one, so an
    operator debugging a rejected token sees everything wrong with the chain at
    once.
    """
    errors = []
    now = now or utcnow()

    if not isinstance(chain, (list, tuple)) or not chain:
        return ChainVerification(False, ["chain must be a non-empty list"])
    if len(chain) > MAX_CHAIN_DEPTH:
        return ChainVerification(
            False,
            ["chain depth %d exceeds maximum %d" % (len(chain), MAX_CHAIN_DEPTH)],
        )

    for index, certificate in enumerate(chain):
        if not isinstance(certificate, dict):
            return ChainVerification(
                False, ["chain[%d] is not a certificate object" % index]
            )
        if certificate.get("kc_version") != PROTOCOL_VERSION:
            errors.append(
                "chain[%d] has unsupported kc_version %r"
                % (index, certificate.get("kc_version"))
            )
        if certificate.get("cert_type") not in CERT_TYPES:
            errors.append(
                "chain[%d] has unknown cert_type %r"
                % (index, certificate.get("cert_type"))
            )
        if is_expired(certificate, now):
            errors.append("%s is expired" % (subject_reference(certificate),))
        if is_not_yet_valid(certificate, now):
            errors.append("%s is not yet valid" % (subject_reference(certificate),))
        if is_revoked is not None and is_revoked(certificate):
            errors.append("%s is revoked" % (subject_reference(certificate),))

    root = chain[-1]
    if root.get("cert_type") != CERT_TYPE_ROOT:
        errors.append("chain does not terminate in a root certificate")
    elif not (root.get("issuer") or {}).get("self_signed"):
        errors.append("root certificate is not self-signed")

    for index, certificate in enumerate(chain):
        issuer_certificate = root if index == len(chain) - 1 else chain[index + 1]
        issuer_jwk = (issuer_certificate.get("subject") or {}).get("public_key")
        if not isinstance(issuer_jwk, dict):
            errors.append("chain[%d] issuer has no usable public key" % index)
            continue
        try:
            verify_signature(certificate, issuer_jwk)
        except (SignatureError, ValidationError) as exc:
            errors.append(
                "invalid signature on %s: %s" % (subject_reference(certificate), exc)
            )
        if index != len(chain) - 1:
            _check_link(certificate, issuer_certificate, errors)

    root_key_id = (root.get("subject") or {}).get("key_id")
    trusted = set(trusted_root_key_ids or ())
    if root_key_id not in trusted:
        errors.append("root key %s is not trusted" % root_key_id)

    leaf = chain[0]
    return ChainVerification(
        valid=not errors,
        errors=errors,
        root_key_id=root_key_id,
        subject=leaf.get("subject"),
        capabilities=leaf.get("capabilities") or [],
        chain_length=len(chain),
    )
