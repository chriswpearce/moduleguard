"""Release-content audit behavior."""

import zipfile

import pytest

from moduleguard.errors import ProtectionError
from moduleguard.inspector import inspect_release


def _minimal_release(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    (release / "sample.cp39-win_amd64.pyd").write_bytes(b"native-binary-placeholder")
    wheel = release / "sample-1.0.0-cp39-cp39-win_amd64.whl"
    with zipfile.ZipFile(str(wheel), "w") as archive:
        archive.writestr("sample.cp39-win_amd64.pyd", b"native-binary-placeholder")
        archive.writestr("sample-1.0.0.dist-info/METADATA", "Name: sample\nVersion: 1.0.0\n")
    return release


def test_minimal_binary_release_passes(tmp_path):
    report = inspect_release(_minimal_release(tmp_path))
    assert report["passed"] is True
    assert report["wheel_count"] == 1
    assert report["extension_count"] == 1


def test_python_source_in_release_fails(tmp_path):
    release = _minimal_release(tmp_path)
    (release / "sample.py").write_text("SECRET = 1\n", encoding="utf-8")
    with pytest.raises(ProtectionError, match="Forbidden release file"):
        inspect_release(release)


def test_source_inside_wheel_fails(tmp_path):
    release = _minimal_release(tmp_path)
    wheel = next(release.glob("*.whl"))
    with zipfile.ZipFile(str(wheel), "a") as archive:
        archive.writestr("sample.py", "SECRET = 1\n")
    with pytest.raises(ProtectionError, match="forbidden member"):
        inspect_release(release)


def test_forbidden_text_fails(tmp_path):
    release = _minimal_release(tmp_path)
    with pytest.raises(ProtectionError, match="forbidden text"):
        inspect_release(release, ["native-binary-placeholder"])
