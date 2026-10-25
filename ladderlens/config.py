"""Configuration loading and repository paths."""
from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "harness" / "bin"
DEFAULT_CONFIG = ROOT / "configs" / "benchmark.toml"
FIXTURES = ROOT / "fixtures"
RESULTS = ROOT / "results"

ARMS = ("plain", "mtl1", "mtl")
ARM_LABEL = {
    "plain": "A: plain SLH-DSA, per record",
    "mtl1": "B: MTL, batch of one",
    "mtl": "C: MTL, batch of N",
}


def load(path: str | Path | None = None) -> dict:
    path = Path(path) if path else DEFAULT_CONFIG
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    cfg["_path"] = str(path)
    return cfg


def fixture_path(cfg: dict) -> Path:
    w = cfg["workload"]
    return FIXTURES / f"zone_seed{w['seed']}.bin"


def fixture_size(cfg: dict) -> int:
    """Records needed by the largest benchmark cell and by every cache run."""
    sizes = max(cfg["workload"]["sizes"])
    c = cfg.get("cache", {})
    growth = 0
    if c.get("growth_every") and c.get("growth_size"):
        growth = ((c["queries"] - 1) // c["growth_every"]) * c["growth_size"]
    return max(sizes, c.get("initial", 0) + growth)
