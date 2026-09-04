"""ModuleGuard exception hierarchy."""


class ModuleGuardError(Exception):
    """Base class for expected user-facing ModuleGuard failures."""


class DurationError(ModuleGuardError):
    """Raised when a licence duration or expiry is invalid."""


class DocumentError(ModuleGuardError):
    """Raised when a request or licence document is malformed."""


class LicenseError(ModuleGuardError):
    """Raised when a licence cannot authorize the current operation."""


class ProtectionError(ModuleGuardError):
    """Raised when a target module cannot be protected or built."""
