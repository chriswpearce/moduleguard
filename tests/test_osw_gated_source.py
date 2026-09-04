"""Compare the licence-gated OSW source copy with the maintained baseline."""

import importlib.util
import inspect
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from moduleguard.licensing import issue_license
from moduleguard.transform import create_protected_source

WORKSPACE = Path(__file__).resolve().parents[2]
SOURCE = next(
    path
    for path in (
        WORKSPACE / "OSW_element_library.py",
        WORKSPACE / "RENAMED_OSW_element_library.py",
    )
    if path.is_file()
)
PRODUCT_ID = "osw-element-library"
VERSION = "2.0.0"
UTC = timezone.utc


def _source_module():
    spec = importlib.util.spec_from_file_location("osw_source_comparison", str(SOURCE))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gated_module(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = datetime.now(UTC).replace(microsecond=0)
    licence = issue_license(
        PRODUCT_ID,
        private_key,
        VERSION,
        duration="7d",
        issued_at=now - timedelta(minutes=1),
    )
    licence_path = tmp_path / "osw.lic"
    licence_path.write_text(json.dumps(licence), encoding="utf-8")
    monkeypatch.setenv("MODULEGUARD_LICENSE_FILE", str(licence_path))

    transformed = create_protected_source(
        SOURCE, "OSW_element_library", PRODUCT_ID, VERSION, public_pem
    )
    module = ModuleType("OSW_element_library")
    exec(compile(transformed, "OSW_element_library.py", "exec"), module.__dict__)
    return module


def test_gated_osw_preserves_functions_call_shapes_and_results(tmp_path, monkeypatch):
    source = _source_module()
    gated = _gated_module(tmp_path, monkeypatch)

    source_functions = {
        name: value for name, value in vars(source).items() if inspect.isfunction(value)
    }
    gated_functions = {
        name: value for name, value in vars(gated).items() if inspect.isfunction(value)
    }
    assert list(gated_functions) == list(source_functions)
    for name in source_functions:
        source_parameters = list(inspect.signature(source_functions[name]).parameters.values())
        gated_parameters = list(inspect.signature(gated_functions[name]).parameters.values())
        assert len(gated_parameters) == len(source_parameters)
        assert [parameter.kind for parameter in gated_parameters] == [
            parameter.kind for parameter in source_parameters
        ]
        assert [parameter.default for parameter in gated_parameters] == [
            parameter.default for parameter in source_parameters
        ]
        assert not gated_functions[name].__doc__

    vector = np.array([-0.02, -0.001, 0.0, 0.001, 0.02])
    calls = [
        ("conic", (vector, 1.0, 2.0, 3.0, 0.4)),
        ("PISA_clay_lateral_load_reaction", (vector, 5.0, 8.0, 100000.0, 20e6)),
        (
            "PISA_sand_lateral_load_reaction",
            (vector, 5.0, 8.0, 30.0, 50000.0, 30e6, 0.6),
        ),
        (
            "Ke_2D_5DOF_PISA_Clay_TimoshenkoBeam",
            (0.0, 0.0, 0.0, 2.0, 0.001, 0.0001, 5.0, 8.0, 100000.0, 20e6),
        ),
        (
            "Freaction_2D_5DOF_PISA_Sand_TimoshenkoBeam",
            (
                0.0,
                0.0,
                0.0,
                2.0,
                0.001,
                0.0001,
                5.0,
                8.0,
                30.0,
                50000.0,
                30e6,
                0.6,
            ),
        ),
        ("Me_2D_5DOF_Consist_TimoshenkoBeam", (0.0, 0.0, 0.0, 2.0, 1.0, 7850.0)),
        ("B_2D_BernoulliEulerBeam", (0.25, 2.0)),
    ]
    for name, arguments in calls:
        expected = getattr(source, name)(*arguments)
        actual = getattr(gated, name)(*arguments)
        np.testing.assert_allclose(actual, expected, rtol=1e-12, atol=1e-12)
