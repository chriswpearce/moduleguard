"""Compatibility baseline for the first proprietary target module."""

import importlib.util
import inspect
from pathlib import Path

import numpy as np

WORKSPACE = Path(__file__).resolve().parents[2]
SOURCE = next(
    path
    for path in (
        WORKSPACE / "OSW_element_library.py",
        WORKSPACE / "RENAMED_OSW_element_library.py",
    )
    if path.is_file()
)
PUBLIC_FUNCTIONS = [
    "Ke_2D_5DOF_Struct_TimoshenkoBeam",
    "conic",
    "PISA_clay_lateral_load_reaction",
    "PISA_clay_distributed_moment_reaction",
    "PISA_clay_base_shear_reaction",
    "PISA_clay_base_moment_reaction",
    "PISA_sand_lateral_load_reaction",
    "PISA_sand_distributed_moment_reaction",
    "PISA_sand_base_shear_reaction",
    "PISA_sand_base_moment_reaction",
    "Ke_2D_5DOF_PISA_Clay_TimoshenkoBeam",
    "Ke_2D_5DOF_PISA_Sand_TimoshenkoBeam",
    "Freaction_2D_5DOF_PISA_Clay_TimoshenkoBeam",
    "Freaction_2D_5DOF_PISA_Sand_TimoshenkoBeam",
    "Me_2D_5DOF_Consist_TimoshenkoBeam",
    "B_2D_BernoulliEulerBeam",
]


def load_source_module():
    spec = importlib.util.spec_from_file_location("osw_source_baseline", str(SOURCE))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_public_api_and_signatures():
    module = load_source_module()
    functions = [name for name, value in vars(module).items() if inspect.isfunction(value)]
    assert functions == PUBLIC_FUNCTIONS
    assert str(inspect.signature(module.PISA_clay_lateral_load_reaction)) == "(v, depth, D, su, G0)"
    assert str(inspect.signature(module.PISA_sand_distributed_moment_reaction)) == "(v, psi, depth, D, L_total, sigma_vi, G0, Dr)"


def test_conic_scalar_and_array_branches():
    module = load_source_module()
    scalar = module.conic(0.25, 1.0, 2.0, 3.0, 0.4)
    vector = module.conic(np.array([-2.0, -0.25, 0.0, 0.25, 2.0]), 1.0, 2.0, 3.0, 0.4)
    assert isinstance(scalar, float)
    assert vector.shape == (5,)
    np.testing.assert_allclose(vector[[0, -1]], [-2.0, 2.0])
    np.testing.assert_allclose(vector[1], -vector[3])
    assert vector[2] == 0.0


def test_representative_reactions_and_matrices():
    module = load_source_module()
    v = np.array([-0.01, 0.0, 0.01])
    clay = module.PISA_clay_lateral_load_reaction(v, 5.0, 8.0, 100000.0, 20e6)
    sand = module.PISA_sand_lateral_load_reaction(v, 5.0, 8.0, 30.0, 50000.0, 30e6, 0.6)
    assert clay.shape == (3,)
    assert sand.shape == (3,)
    np.testing.assert_allclose(clay, -clay[::-1])
    np.testing.assert_allclose(sand, -sand[::-1])

    structural = module.Ke_2D_5DOF_Struct_TimoshenkoBeam(
        0.0, 0.0, 0.0, 2.0, 210e9, 1.0, 0.2, 80e9, 0.8
    )
    mass = module.Me_2D_5DOF_Consist_TimoshenkoBeam(0.0, 0.0, 0.0, 2.0, 1.0, 7850.0)
    curvature = module.B_2D_BernoulliEulerBeam(0.0, 2.0)
    assert structural.shape == (5, 5)
    assert mass.shape == (5, 5)
    assert curvature.shape == (1, 4)
    np.testing.assert_allclose(structural, structural.T)
    np.testing.assert_allclose(mass, mass.T)
