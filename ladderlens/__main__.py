"""Command line: python3 -m ladderlens <command> [--config FILE]"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import config


def main(argv=None) -> int:
    try:
        return _main(argv)
    except RuntimeError as err:  # HarnessError and other run-time failures
        print(f"error: {err}", file=sys.stderr)
        return 1


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ladderlens", description="MTL-mode DNSSEC signature benchmark (PS-036)")
    ap.add_argument("--config", default=None, help="TOML configuration (default: configs/benchmark.toml)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fixtures", help="generate the synthetic signed-zone fixture")
    p = sub.add_parser("plan", help="time a short pilot and plan trials within the budget")
    p.add_argument("--out", default=str(config.RESULTS / "plan.json"))
    r = sub.add_parser("run", help="execute the plan: interleaved benchmark rounds and cache replays")
    r.add_argument("--plan", default=str(config.RESULTS / "plan.json"))
    r.add_argument("--out", default=None, help="run directory (default: results/runs/<UTC time>)")
    rp = sub.add_parser("report", help="build tables, charts and report.md for a run")
    rp.add_argument("run", nargs="?", default=None, help="run directory (default: latest)")
    rp.add_argument("--readme", action="store_true", help="also write the run summary into README.md")
    sub.add_parser("verify", help="check correctness and exact sizes in this environment")
    sub.add_parser("demo", help="short narrated walk-through")
    args = ap.parse_args(argv)
    cfg = config.load(args.config)

    if args.cmd == "fixtures":
        from . import fixtures
        meta = fixtures.ensure(cfg)
        print(f"{config.fixture_path(cfg)}: {meta['records']} RRsets, sha256 {meta['sha256'][:16]}")
    elif args.cmd == "plan":
        from . import plan
        plan.main(cfg, Path(args.out))
    elif args.cmd == "run":
        from . import run
        _, failures = run.main(cfg, Path(args.plan), Path(args.out) if args.out else None)
        return 1 if failures else 0
    elif args.cmd == "report":
        from . import report
        target = Path(args.run) if args.run else latest_run()
        print(report.build(cfg, target))
        if args.readme:
            report.update_readme(target, config.ROOT / "README.md")
            print("README.md results block updated")
    elif args.cmd == "verify":
        from . import verify
        return verify.main(cfg)
    elif args.cmd == "demo":
        from . import demo
        return demo.main(cfg)
    return 0


def latest_run() -> Path:
    """The most recently finished run, including the committed results/final."""
    candidates = [p.parent for p in (config.RESULTS / "runs").glob("*/manifest.json")]
    final = config.RESULTS / "final" / "manifest.json"
    if final.exists():
        candidates.append(final.parent)
    candidates = [p for p in candidates if p.exists()]
    if not candidates:
        raise SystemExit("no runs found under results/; run `make bench` first")
    return max(candidates, key=lambda p: (p / "manifest.json").stat().st_mtime)


if __name__ == "__main__":
    sys.exit(main())
