"""Product identifier and central licence-path helpers."""

import hashlib
import os
import re
from pathlib import Path

from .errors import LicenseError

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._-]+")


def validate_product_id(product_id: str) -> str:
    """Validate the product identifier used in signed documents."""
    product_id = product_id.strip()
    if not product_id or len(product_id) > 128:
        raise LicenseError("Product ID must contain between 1 and 128 characters")
    if any(character in product_id for character in "\r\n\x00"):
        raise LicenseError("Product ID contains an invalid control character")
    return product_id


def product_slug(product_id: str) -> str:
    """Return a safe filename component for a product ID."""
    product_id = validate_product_id(product_id)
    slug = _SAFE_ID_RE.sub("-", product_id).strip("-.")
    if not slug:
        slug = hashlib.sha256(product_id.encode("utf-8")).hexdigest()[:16]
    return slug[:80]


def default_license_path(product_id: str) -> Path:
    """Return the per-user default path for a product licence."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise LicenseError("LOCALAPPDATA is not defined; set MODULEGUARD_LICENSE_FILE")
    return (
        Path(local_app_data)
        / "ModuleGuard"
        / "licenses"
        / (product_slug(product_id) + ".lic")
    )