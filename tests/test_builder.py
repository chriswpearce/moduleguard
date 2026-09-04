"""No-admin native builder helpers and wheel contracts."""

import csv
import hashlib
import io
import zipfile

import pytest

from moduleguard.builder import _build_wheel, _hash_record, _zig_environment
from moduleguard.errors import ProtectionError


def test_hash_record_is_urlsafe_sha256():
    value = _hash_record(b"protected")
    assert value.startswith("sha256=")
    assert "+" not in value
    assert "/" not in value
    assert not value.endswith("=")


def test_build_wheel_contains_only_binary_and_metadata(tmp_path):
    extension = tmp_path / "Sample.cp39-win_amd64.pyd"
    extension.write_bytes(b"native-extension")

    wheel = _build_wheel(
        extension,
        tmp_path,
        "Sample",
        "2.0.0",
        ["cryptography>=41", "numpy>=1.26"],
    )

    assert wheel.name.startswith("moduleguard_protected_sample-2.0.0-cp")
    with zipfile.ZipFile(str(wheel)) as archive:
        names = archive.namelist()
        assert extension.name in names
        assert not any(name.endswith((".py", ".c", ".h")) for name in names)
        metadata_name = next(name for name in names if name.endswith("/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
        assert "Name: moduleguard-protected-sample" in metadata
        assert "Requires-Dist: cryptography>=41" in metadata
        assert "Requires-Dist: numpy>=1.26" in metadata

        record_name = next(name for name in names if name.endswith("/RECORD"))
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
        records = {row[0]: row[1:] for row in rows}
        assert records[record_name] == ["", ""]
        for name in names:
            if name == record_name:
                continue
            data = archive.read(name)
            assert records[name] == [_hash_record(data), str(len(data))]


def test_build_wheel_rejects_invalid_version_and_dependency(tmp_path):
    extension = tmp_path / "sample.cp39-win_amd64.pyd"
    extension.write_bytes(hashlib.sha256(b"sample").digest())
    with pytest.raises(ProtectionError, match="Invalid product version"):
        _build_wheel(extension, tmp_path, "sample", "not a version", [])
    with pytest.raises(ProtectionError, match="Invalid runtime dependency"):
        _build_wheel(extension, tmp_path, "sample", "1.0", ["not a requirement!"])


def test_zig_environment_prepends_python_packaged_compiler():
    environment = _zig_environment()
    first_path = environment["PATH"].split(__import__("os").pathsep)[0]
    assert first_path.lower().endswith("ziglang")
