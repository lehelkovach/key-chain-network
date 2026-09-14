"""Error taxonomy shared by the KeyChain library, CLI and HTTP surface.

Every error carries the HTTP status and machine-readable code the API should
return, so the Flask layer never has to re-derive them.
"""


class KeyChainError(Exception):
    """Base class for all expected KeyChain failures."""

    status = 400
    code = "keychain_error"

    def __init__(self, message, details=None, **extra):
        super().__init__(message)
        self.message = message
        self.details = list(details or [])
        self.extra = dict(extra)

    def to_dict(self):
        payload = {"error": self.message, "code": self.code}
        if self.details:
            payload["details"] = self.details
        payload.update(self.extra)
        return payload


class ValidationError(KeyChainError):
    status = 400
    code = "invalid_request"


class UnauthorizedError(KeyChainError):
    status = 401
    code = "unauthorized"


class NotFoundError(KeyChainError):
    status = 404
    code = "not_found"


class ConflictError(KeyChainError):
    status = 409
    code = "conflict"

    def __init__(self, message, conflict_code, details=None, **extra):
        super().__init__(message, details=details, **extra)
        self.conflict_code = conflict_code

    def to_dict(self):
        payload = super().to_dict()
        payload["conflict_code"] = self.conflict_code
        return payload


class SignatureError(KeyChainError):
    """A signature was structurally valid but did not verify."""

    status = 400
    code = "invalid_signature"


class TrustError(KeyChainError):
    """A certificate chain did not terminate in a trusted root."""

    status = 400
    code = "untrusted_chain"


class RevokedError(KeyChainError):
    status = 403
    code = "revoked"


class CustodyError(KeyChainError):
    """A signing operation needs a private key the service does not hold."""

    status = 409
    code = "key_not_in_custody"


class ConfigurationError(KeyChainError):
    status = 500
    code = "misconfigured"
