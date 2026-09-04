"""Protected-source generation behavior."""

import ast
from pathlib import Path

import pytest

from moduleguard.errors import ProtectionError
from moduleguard.transform import create_protected_source, validate_module_name

PUBLIC_KEY = b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"


def test_gate_is_inserted_after_future_import_and_docstring_is_removed(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        '"""sample module"""\nfrom __future__ import annotations\n\nVALUE = 42\n',
        encoding="utf-8",
    )
    transformed = create_protected_source(
        source, "sample", "sample-product", "1.0.0", PUBLIC_KEY
    )
    tree = ast.parse(transformed)
    assert ast.get_docstring(tree) is None
    assert "sample module" not in transformed
    assert "from __future__ import annotations" in transformed
    assert transformed.index("from __future__ import annotations") < transformed.index(
        "import base64 as"
    )
    assert transformed.index("import base64 as") < transformed.index("VALUE = 42")
    assert "ModuleGuard runtime gate" not in transformed
    assert "__moduleguard_fail" not in transformed


@pytest.mark.parametrize("name", ["bad-name", "two.parts", "class", ""])
def test_invalid_module_names(name):
    with pytest.raises(ProtectionError):
        validate_module_name(name)
