"""Signed portable-licence workflows."""

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from moduleguard.documents import canonical_json
from moduleguard.errors import LicenseError
from moduleguard.licensing import LICENSE_TYPE, issue_license, verify_license_document

UTC = timezone.utc
PRODUCT_ID = "osw-element-library"
VERSION = "2.0.0"


def issue(duration="7d", required_url=None, required_path=None):
    private_key = Ed25519PrivateKey.generate()
    issued_at = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    document = issue_license(
        PRODUCT_ID,
        private_key,
        VERSION,
        duration=duration,
        issued_at=issued_at,
        required_url=required_url,
        required_path=required_path,
    )
    return private_key, document, issued_at


def verify(private_key, document, now, version=VERSION):
    return verify_license_document(
        document, private_key.public_key(), PRODUCT_ID, version, now=now
    )


def test_issue_and_verify_portable_seven_day_licence():
    private_key, document, issued_at = issue()
    payload = verify(private_key, document, issued_at + timedelta(days=6))

    assert payload["document_type"] == LICENSE_TYPE
    assert payload["schema_version"] == 3
    assert payload["licence_scope"] == "portable"
    assert payload["requested_duration"] == "7d"
    assert payload["expires_at"] == "2026-09-10T12:00:00Z"
    assert payload["required_url"] is None
    assert payload["required_path"] is None
    assert "request_id" not in payload
    assert "machine_fingerprint" not in payload


@pytest.mark.parametrize(
    ("duration", "expected"),
    [
        ("1mo", "2026-10-03T12:00:00Z"),
        ("6mo", "2027-03-03T12:00:00Z"),
        ("1y", "2027-09-03T12:00:00Z"),
    ],
)
def test_configurable_duration(duration, expected):
    _, document, _ = issue(duration)
    assert document["payload"]["expires_at"] == expected


def test_explicit_expiry():
    private_key = Ed25519PrivateKey.generate()
    issued_at = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    expiry = datetime(2027, 1, 1, tzinfo=UTC)
    document = issue_license(
        PRODUCT_ID,
        private_key,
        VERSION,
        expires_at=expiry,
        issued_at=issued_at,
    )
    assert document["payload"]["expires_at"] == "2027-01-01T00:00:00Z"
    assert document["payload"]["requested_duration"] == "until:2027-01-01T00:00:00Z"


def test_required_url_is_signed_and_verified():
    url = "https://intranet.example.test/health"
    private_key, document, issued_at = issue(required_url=url)
    assert verify(private_key, document, issued_at)["required_url"] == url

    document["payload"]["required_url"] = "https://public.example.test/"
    with pytest.raises(LicenseError, match="signature"):
        verify(private_key, document, issued_at)


def test_required_path_is_signed_and_verified():
    path = r"P:\GBEMF\Systems Engineering\test.txt"
    private_key, document, issued_at = issue(required_path=path)
    assert verify(private_key, document, issued_at)["required_path"] == path

    document["payload"]["required_path"] = r"P:\different.txt"
    with pytest.raises(LicenseError, match="signature"):
        verify(private_key, document, issued_at)


@pytest.mark.parametrize(
    "url",
    ["", "intranet.example.test", "ftp://intranet.example.test", "https:///missing-host"],
)
def test_invalid_required_url_is_rejected(url):
    with pytest.raises(LicenseError, match="Required URL"):
        issue_license(PRODUCT_ID, Ed25519PrivateKey.generate(), VERSION, required_url=url)


@pytest.mark.parametrize("path", ["", "relative\\folder", "relative.txt"])
def test_invalid_required_path_is_rejected(path):
    with pytest.raises(LicenseError, match="Required path"):
        issue_license(
            PRODUCT_ID,
            Ed25519PrivateKey.generate(),
            VERSION,
            required_path=path,
        )


def test_required_url_and_path_are_mutually_exclusive():
    with pytest.raises(LicenseError, match="cannot both"):
        issue_license(
            PRODUCT_ID,
            Ed25519PrivateKey.generate(),
            VERSION,
            required_url="https://intranet.example.test/",
            required_path=r"P:\approved",
        )


def test_tampering_breaks_signature():
    private_key, document, issued_at = issue()
    document["payload"]["expires_at"] = "2099-01-01T00:00:00Z"
    with pytest.raises(LicenseError, match="signature"):
        verify(private_key, document, issued_at)


def test_wrong_product_version_is_rejected():
    private_key, document, issued_at = issue()
    with pytest.raises(LicenseError, match="product version"):
        verify(private_key, document, issued_at, version="3.0.0")


def test_expired_licence_is_rejected_at_boundary():
    private_key, document, issued_at = issue()
    with pytest.raises(LicenseError, match="expired"):
        verify(private_key, document, issued_at + timedelta(days=7))


def test_old_machine_bound_schema_is_rejected():
    private_key, document, issued_at = issue()
    document["payload"]["schema_version"] = 2
    document["signature"] = base64.b64encode(
        private_key.sign(canonical_json(document["payload"]))
    ).decode("ascii")
    with pytest.raises(LicenseError, match="new portable licence"):
        verify(private_key, document, issued_at)


def test_bad_base64_signature_is_rejected():
    private_key, document, issued_at = issue()
    document["signature"] = base64.b64encode(b"not-a-signature").decode("ascii")
    with pytest.raises(LicenseError, match="signature"):
        verify(private_key, document, issued_at)
