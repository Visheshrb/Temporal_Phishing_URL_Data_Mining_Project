"""Shared fixtures: the real config, and a copy whose paths point into a temporary data root."""

import copy

import pytest

from src.config import ROOT, load_config


@pytest.fixture
def cfg() -> dict:
    """config.yaml from the project root, paths resolved."""
    return load_config(ROOT / "config.yaml")


@pytest.fixture
def tmp_cfg(cfg: dict, tmp_path) -> dict:
    """Same config, but every path is re-rooted under tmp_path; directories are created."""
    out = copy.deepcopy(cfg)
    for name, p in cfg["paths"].items():
        new = tmp_path / p.relative_to(ROOT)
        (new.parent if new.suffix else new).mkdir(parents=True, exist_ok=True)
        out["paths"][name] = new
    return out
