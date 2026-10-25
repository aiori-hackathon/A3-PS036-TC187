"""Reproducibility manifest: what ran, where, and on which exact inputs."""
from __future__ import annotations

import hashlib
import os
import platform
import subprocess
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from .config import BIN, ROOT

PACKAGES = ("dnspython", "numpy", "scipy", "pandas", "matplotlib")
PIN_VARS = ("MTL_REF_COMMIT", "MTL_CFLAGS", "OPENSSL_SHA", "LIBOQS_SHA", "LADDERLENS_IMAGE")


def sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def _git(*args: str) -> str | None:
    try:
        return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def cpu() -> dict:
    info = {"logical_cpus": os.cpu_count()}
    try:
        text = Path("/proc/cpuinfo").read_text()
    except OSError:
        return info
    for line in text.splitlines():
        key, _, val = line.partition(":")
        key = key.strip()
        if key == "model name" and "model" not in info:
            info["model"] = val.strip()
        elif key == "cpu MHz" and "mhz_at_start" not in info:
            info["mhz_at_start"] = float(val)
        elif key == "flags" and "isa" not in info:
            flags = set(val.split())
            info["isa"] = sorted(flags & {"avx2", "avx512f", "sha_ni", "aes", "bmi2", "hypervisor"})
    try:
        mem = Path("/proc/meminfo").read_text().splitlines()[0]
        info["mem_total_kb"] = int(mem.split()[1])
    except (OSError, IndexError, ValueError):
        pass
    gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    info["governor"] = gov.read_text().strip() if gov.exists() else "unavailable"
    return info


def collect(cfg: dict, fixture_meta: dict | None = None) -> dict:
    status = _git("status", "--porcelain")
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config": {k: v for k, v in cfg.items() if not k.startswith("_")},
        "config_path": cfg.get("_path"),
        "git": {"commit": _git("rev-parse", "HEAD"), "dirty": bool(status) if status is not None else None},
        "host": {"platform": platform.platform(), "python": platform.python_version(),
                 "in_pinned_image": os.environ.get("LADDERLENS_IMAGE") == "1", "cpu": cpu(),
                 "codespace": os.environ.get("CODESPACE_NAME") is not None},
        "pins": {k: os.environ.get(k) for k in PIN_VARS},
        "python_packages": {p: _version(p) for p in PACKAGES},
        "binaries": {name: sha256(BIN / name) for name in ("bench", "cachesim")},
        "fixture": fixture_meta,
    }


def _version(pkg: str) -> str | None:
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return None
