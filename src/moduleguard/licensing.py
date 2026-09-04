"""Portable licence issuance and verification."""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from urllib.parse import urlsplit

from .documents import canonical_json, read_json_object, write_json_object
from .duration import calculate_expiry, ensure_utc, parse_duration, parse_utc, to_utc_text
from .errors import DocumentError, LicenseError
from .product import validate_product_id

LICENSE_TYPE = "moduleguard-license"
LICENSE_SCHEMA_VERSION = 3
LICENSE_SCOPE = "portable"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _require_text(document: Dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise DocumentError("Document field {!r} must be a non-empty string".format(key))
    return value


def validate_required_url(required_url: Optional[str]) -> Optional[str]:
    """Validate and normalise an optional HTTP(S) availability-check URL."""
    if required_url is None:
        return None
    value = required_url.strip()
    if not value:
        raise LicenseError("Required URL must not be empty")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LicenseError("Required URL must be an absolute HTTP or HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise LicenseError("Required URL must not contain embedded credentials")
    return value


def validate_required_path(required_path: Optional[str]) -> Optional[str]:
    """Validate an optional absolute file or folder availability-check path."""
    if required_path is None:
        return None
    value = required_path.strip()
    if not value:
        raise LicenseError("Required path must not be empty")
    if "\x00" in value:
        raise LicenseError("Required path contains an invalid null character")
    if not (Path(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        raise LicenseError("Required path must be absolute")
    return value


def issue_license(
    product_id: str,
    private_key: Ed25519PrivateKey,
    product_version: str,
    *,
    duration: str = "7d",
    expires_at: Optional[datetime] = None,
    issued_at: Optional[datetime] = None,
    required_url: Optional[str] = None,
    required_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a signed portable licence without a machine request."""
    product_id = validate_product_id(product_id)
    if not product_version.strip():
        raise LicenseError("Product version must not be empty")
    required_url = validate_required_url(required_url)
    required_path = validate_required_path(required_path)
    if required_url is not None and required_path is not None:
        raise LicenseError("Required URL and required path cannot both be specified")
    starts_at = ensure_utc(issued_at or _now_utc()).replace(microsecond=0)
    if expires_at is not None:
        expiry = ensure_utc(expires_at).replace(microsecond=0)
        duration_text = "until:" + to_utc_text(expiry)
    else:
        parsed_duration = parse_duration(duration)
        expiry = calculate_expiry(starts_at, parsed_duration)
        duration_text = str(parsed_duration)
    if expiry <= starts_at:
        raise LicenseError("Licence expiry must be later than its issue time")

    payload: Dict[str, Any] = {
        "document_type": LICENSE_TYPE,
        "schema_version": LICENSE_SCHEMA_VERSION,
        "licence_scope": LICENSE_SCOPE,
        "license_id": str(uuid.uuid4()),
        "product_id": product_id,
        "product_version": product_version.strip(),
        "issued_at": to_utc_text(starts_at),
        "not_before": to_utc_text(starts_at),
        "expires_at": to_utc_text(expiry),
        "requested_duration": duration_text,
        "required_url": required_url,
        "required_path": required_path,
    }
    signature = private_key.sign(canonical_json(payload))
    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def write_issued_license(
    output_path: Path,
    document: Dict[str, Any],
    ledger_path: Optional[Path] = None,
) -> None:
    """Write a licence and optionally append a non-secret issuance record."""
    write_json_object(output_path, document)
    if ledger_path is None:
        return
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise DocumentError("Cannot ledger a malformed licence")
    record = {
        key: payload.get(key)
        for key in (
            "license_id",
            "licence_scope",
            "product_id",
            "product_version",
            "requested_duration",
            "required_url",
            "required_path",
            "issued_at",
            "not_before",
            "expires_at",
        )
    }
    record["license_sha256"] = hashlib.sha256(canonical_json(document)).hexdigest()
    ledger_path = ledger_path.resolve()
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with ledger_path.open("a", encoding="utf-8", newline="\n") as ledger:
            ledger.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    except OSError as exc:
        raise DocumentError("Cannot append issuance ledger {}: {}".format(ledger_path, exc)) from exc


def verify_license_document(
    document: Dict[str, Any],
    public_key: Ed25519PublicKey,
    product_id: str,
    product_version: str,
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Verify a signed licence and return its authenticated payload."""
    payload = document.get("payload")
    signature_text = document.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature_text, str):
        raise LicenseError("Licence must contain payload and signature fields")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        public_key.verify(signature, canonical_json(payload))
    except (ValueError, InvalidSignature) as exc:
        raise LicenseError("Licence signature is invalid") from exc

    if payload.get("document_type") != LICENSE_TYPE:
        raise LicenseError("The document is not a ModuleGuard licence")
    if payload.get("schema_version") != LICENSE_SCHEMA_VERSION:
        raise LicenseError(
            "Unsupported licence schema version; issue a new portable licence"
        )
    for field in (
        "license_id",
        "licence_scope",
        "product_id",
        "product_version",
        "issued_at",
        "not_before",
        "expires_at",
        "requested_duration",
    ):
        try:
            _require_text(payload, field)
        except DocumentError as exc:
            raise LicenseError(str(exc)) from exc

    if payload["licence_scope"] != LICENSE_SCOPE:
        raise LicenseError("Licence is not portable")
    try:
        validate_required_url(payload.get("required_url"))
    except LicenseError as exc:
        raise LicenseError("Licence contains an invalid required URL") from exc
    try:
        validate_required_path(payload.get("required_path"))
    except LicenseError as exc:
        raise LicenseError("Licence contains an invalid required path") from exc
    if payload.get("required_url") is not None and payload.get("required_path") is not None:
        raise LicenseError("Licence cannot require both a URL and a path")

    if payload["product_id"] != product_id:
        raise LicenseError("Licence is for a different product")
    if payload["product_version"] != product_version:
        raise LicenseError(
            "Licence is for product version {}, not {}".format(
                payload["product_version"], product_version
            )
        )
    try:
        current_time = ensure_utc(now or _now_utc()).replace(microsecond=0)
    except Exception as exc:
        raise LicenseError("Current validation time must include a UTC offset") from exc
    try:
        not_before = parse_utc(str(payload["not_before"]))
        expires_at = parse_utc(str(payload["expires_at"]))
        issued_at = parse_utc(str(payload["issued_at"]))
    except Exception as exc:
        raise LicenseError("Licence contains an invalid date/time") from exc
    if expires_at <= not_before or not_before < issued_at:
        raise LicenseError("Licence validity dates are inconsistent")
    if current_time < not_before:
        raise LicenseError("Licence is not valid until {}".format(payload["not_before"]))
    if current_time >= expires_at:
        raise LicenseError("Licence expired at {}".format(payload["expires_at"]))
    return payload


def verify_license(
    path: Path,
    public_key: Ed25519PublicKey,
    product_id: str,
    product_version: str,
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Read and verify a portable licence file."""
    try:
        document = read_json_object(path)
    except DocumentError as exc:
        raise LicenseError(str(exc)) from exc
    return verify_license_document(
        document,
        public_key,
        product_id,
        product_version,
        now=now,
    )
