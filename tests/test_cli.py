"""Command-line argument and help contracts documented in the manual."""

from pathlib import Path

import pytest

from moduleguard.cli import main


def test_top_level_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    for command in ("keygen", "issue", "protect", "inspect", "license-path"):
        assert command in output
    assert "request" not in output


def test_issue_rejects_conflicting_duration_and_expiry(capsys):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "issue",
                "--product-id",
                "sample-product",
                "--private-key",
                "private.pem",
                "--product-version",
                "1.0.0",
                "--duration",
                "7d",
                "--expires-at",
                "2027-01-01T00:00:00Z",
                "--output",
                "output.lic",
            ]
        )
    assert exc.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_issue_help_describes_portable_options(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["issue", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--product-id" in output
    assert "--required-url" in output
    assert "--required-path" in output
    assert "--request" not in output


def test_issue_rejects_conflicting_url_and_path(capsys):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "issue",
                "--product-id",
                "sample-product",
                "--private-key",
                "private.pem",
                "--product-version",
                "1.0.0",
                "--required-url",
                "https://intranet.example.test/",
                "--required-path",
                r"P:\approved",
                "--output",
                "output.lic",
            ]
        )
    assert exc.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_license_path_command(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert main(["license-path", "--product-id", "sample product"]) == 0
    output = capsys.readouterr().out.strip()
    assert Path(output) == tmp_path / "ModuleGuard" / "licenses" / "sample-product.lic"
