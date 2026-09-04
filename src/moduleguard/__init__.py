"""ModuleGuard public package API."""

from .duration import calculate_expiry, parse_duration, parse_utc, to_utc_text
from .licensing import issue_license, verify_license

__all__ = [
    "calculate_expiry",
    "issue_license",
    "parse_duration",
    "parse_utc",
    "to_utc_text",
    "verify_license",
]

__version__ = "0.3.0"
