from pathlib import Path

import pytest

from src.config import REQUIRED_KEYS, ROOT, load_config


def test_loads_with_required_keys(cfg):
    for key in REQUIRED_KEYS:
        assert key in cfg
    assert cfg["seed"] == 42


def test_paths_are_absolute_under_root(cfg):
    for p in cfg["paths"].values():
        assert isinstance(p, Path) and p.is_absolute()
    assert cfg["paths"]["raw"] == ROOT / "data" / "raw"


def test_default_path_finds_root_config(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert load_config()["seed"] == 42


def test_missing_key_raises(tmp_path):
    bad = tmp_path / "config.yaml"
    bad.write_text("seed: 42\npaths: {raw: data/raw}\n", encoding="utf-8")
    with pytest.raises(KeyError):
        load_config(bad)


def test_tmp_cfg_redirects_paths(tmp_cfg, tmp_path):
    assert tmp_cfg["paths"]["raw"] == tmp_path / "data" / "raw"
    assert tmp_cfg["paths"]["raw"].is_dir()
