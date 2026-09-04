"""Execute the portable runtime gate as Python before native compilation."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from moduleguard.licensing import issue_license
from moduleguard.transform import create_protected_source

UTC = timezone.utc
PRODUCT_ID = "runtime-gate-test"
VERSION = "1.0.0"
LICENCE_FILENAME = PRODUCT_ID + ".lic"


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _):
        return b"O"


def _materials(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    source = tmp_path / "sample.py"
    source.write_text("VALUE = 42\n", encoding="utf-8")
    transformed = create_protected_source(
        source, "sample", PRODUCT_ID, VERSION, public_pem
    )
    return private_key, source, transformed


def _licence(private_key, required_url=None, required_path=None):
    now = datetime.now(UTC).replace(microsecond=0)
    return issue_license(
        PRODUCT_ID,
        private_key,
        VERSION,
        duration="7d",
        issued_at=now - timedelta(minutes=1),
        required_url=required_url,
        required_path=required_path,
    )


def _write(path, licence):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(licence), encoding="utf-8")


def _execute(transformed, source, **extra):
    namespace = {"__name__": "sample", "__file__": str(source)}
    namespace.update(extra)
    exec(compile(transformed, "sample.py", "exec"), namespace)
    return namespace


def test_environment_override_allows_any_filename(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    licence_path = tmp_path / "named-anything.lic"
    _write(licence_path, _licence(private_key))
    monkeypatch.setenv("MODULEGUARD_LICENSE_FILE", str(licence_path))

    namespace = _execute(transformed, source)
    assert namespace["VALUE"] == 42
    assert not any(name.startswith("__moduleguard") for name in namespace)


def test_licence_beside_module_is_found_before_appdata(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    _write(tmp_path / LICENCE_FILENAME, _licence(private_key))
    monkeypatch.delenv("MODULEGUARD_LICENSE_FILE", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "unused-appdata"))

    assert _execute(transformed, source)["VALUE"] == 42


def test_central_appdata_licence_is_found(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    central = tmp_path / "appdata" / "ModuleGuard" / "licenses" / LICENCE_FILENAME
    _write(central, _licence(private_key))
    monkeypatch.delenv("MODULEGUARD_LICENSE_FILE", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))

    assert _execute(transformed, source)["VALUE"] == 42


def test_compiled_extension_location_is_preferred(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    extension_dir = tmp_path / "installed"
    _write(extension_dir / LICENCE_FILENAME, _licence(private_key))
    compiled = type(
        "Compiled", (), {"extension_filename": str(extension_dir / "sample.pyd")}
    )()
    monkeypatch.delenv("MODULEGUARD_LICENSE_FILE", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)

    assert _execute(transformed, source, __compiled__=compiled)["VALUE"] == 42


def test_missing_licence_reports_searched_locations(tmp_path, monkeypatch):
    _, source, transformed = _materials(tmp_path)
    monkeypatch.delenv("MODULEGUARD_LICENSE_FILE", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    with pytest.raises(ImportError, match="licence file not found; searched"):
        _execute(transformed, source)


def test_required_website_success_allows_import(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    licence_path = tmp_path / "portable.lic"
    _write(licence_path, _licence(private_key, "https://intranet.example.test/"))
    monkeypatch.setenv("MODULEGUARD_LICENSE_FILE", str(licence_path))
    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: _Response())

    assert _execute(transformed, source)["VALUE"] == 42


def test_required_website_failure_blocks_import(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    licence_path = tmp_path / "portable.lic"
    _write(licence_path, _licence(private_key, "https://intranet.example.test/"))
    monkeypatch.setenv("MODULEGUARD_LICENSE_FILE", str(licence_path))

    def unavailable(*_args, **_kwargs):
        raise OSError("network unavailable")

    monkeypatch.setattr("urllib.request.urlopen", unavailable)
    with pytest.raises(ImportError, match="required website could not be loaded"):
        _execute(transformed, source)


def test_required_file_can_be_opened(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    required_file = tmp_path / "network" / "test.txt"
    required_file.parent.mkdir()
    required_file.write_text("available", encoding="utf-8")
    licence_path = tmp_path / "portable.lic"
    _write(licence_path, _licence(private_key, required_path=str(required_file)))
    monkeypatch.setenv("MODULEGUARD_LICENSE_FILE", str(licence_path))

    assert _execute(transformed, source)["VALUE"] == 42


def test_required_folder_can_be_opened(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    required_folder = tmp_path / "network" / "approved"
    required_folder.mkdir(parents=True)
    licence_path = tmp_path / "portable.lic"
    _write(licence_path, _licence(private_key, required_path=str(required_folder)))
    monkeypatch.setenv("MODULEGUARD_LICENSE_FILE", str(licence_path))

    assert _execute(transformed, source)["VALUE"] == 42


def test_missing_required_path_blocks_import(tmp_path, monkeypatch):
    private_key, source, transformed = _materials(tmp_path)
    required_path = tmp_path / "disconnected" / "test.txt"
    licence_path = tmp_path / "portable.lic"
    _write(licence_path, _licence(private_key, required_path=str(required_path)))
    monkeypatch.setenv("MODULEGUARD_LICENSE_FILE", str(licence_path))

    with pytest.raises(ImportError, match="required path is not an accessible"):
        _execute(transformed, source)
