"""Thin wrappers around the C harness binaries and their output files."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pandas as pd

from .config import BIN


class HarnessError(RuntimeError):
    """A harness program failed; the message carries the command and the last lines of stderr."""


def binary(name: str) -> Path:
    path = BIN / name
    if not path.exists():
        raise SystemExit(f"{path} not found; run `make harness` first")
    return path


def bench(arm: str, n: int, out: Path, *, records: Path | None, trials: int = 1,
          warmups: int = 0, sample: int = 0, trial_base: int = 1, seed: int = 0,
          algorithm: str | None = None) -> Path:
    cmd = [str(binary("bench")), "--arm", arm, "--batch-size", str(n), "--trials", str(trials),
           "--warmups", str(warmups), "--trial-base", str(trial_base), "--seed", str(seed),
           "--output", str(out)]
    if records:
        cmd += ["--records", str(records)]
    if sample and arm != "mtl" and sample < n:
        cmd += ["--sample", str(sample)]
    if algorithm:
        cmd += ["--algorithm", algorithm]
    _run(cmd)
    return out


def cachesim(out: Path, *, records: Path, initial: int, queries: int, zipf: float, ttl: int,
             growth_every: int = 0, growth_size: int = 0, seed: int = 1,
             algorithm: str | None = None) -> Path:
    cmd = [str(binary("cachesim")), "--records", str(records), "--initial", str(initial),
           "--queries", str(queries), "--zipf", str(zipf), "--ttl", str(ttl), "--seed", str(seed),
           "--output", str(out)]
    if growth_every and growth_size:
        cmd += ["--growth-every", str(growth_every), "--growth-size", str(growth_size)]
    if algorithm:
        cmd += ["--algorithm", algorithm]
    _run(cmd)
    return out


def selftest(algorithm: str | None = None) -> tuple[int, list[str]]:
    """Run harness/bin/selftest; returns its exit status and output lines."""
    cmd = [str(binary("selftest"))] + (["--algorithm", algorithm] if algorithm else [])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout.splitlines()


def _run(cmd: list[str]) -> None:
    # The reference library logs expected lookup misses to stderr; keep only our own lines.
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.strip().splitlines()[-20:])
        raise HarnessError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{tail}")


def read_bench(paths) -> pd.DataFrame:
    frames = [pd.read_csv(p, comment="#") for p in paths]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def read_meta(csv_path: Path) -> dict:
    return json.loads(Path(str(csv_path)[:-4] + ".meta.json").read_text())


def read_cache_summary(csv_path: Path) -> dict:
    return json.loads(Path(str(csv_path)[:-4] + ".summary.json").read_text())
