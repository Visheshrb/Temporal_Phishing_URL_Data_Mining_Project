"""Load config.yaml, the single source of every tunable number."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_KEYS = (
    "seed",
    "paths",
    "sources",
    "study",
    "sampling",
    "network",
    "campaigns",
    "features",
    "model",
    "patterns",
    "families",
    "radar",
    "explain",
    "inject",
    "policy",
    "sensitivity",
)


def load_config(path: str | Path = "config.yaml") -> dict:
    """Read the YAML config and return it as a dict.

    A relative `path` is tried against the working directory, then the project root. Every entry
    under `paths` becomes an absolute pathlib.Path resolved against the config file's folder.
    Raises FileNotFoundError if the file is missing and KeyError if a required top-level key is absent.
    """
    p = Path(path)
    if not p.is_absolute() and not p.exists():
        p = ROOT / p
    if not p.exists():
        raise FileNotFoundError(f"config not found: {path}")

    with p.open(encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    missing = [k for k in REQUIRED_KEYS if k not in cfg]
    if missing:
        raise KeyError(f"config {p} is missing required keys: {missing}")

    base = p.resolve().parent
    cfg["paths"] = {name: (base / rel).resolve() for name, rel in cfg["paths"].items()}
    return cfg
