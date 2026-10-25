"""Run-directory safety: old and new measurements must never mix.

    python3 -m unittest discover -s tests -v      (or: make test)

The first group needs nothing but Python. The end-to-end test needs the harness
(`make harness`) and is skipped without it.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ladderlens import analysis, config, manifest, report, run  # noqa: E402
from ladderlens import plan as planner  # noqa: E402

CSV = ("# test\n"
       "trial,arm,batch_size,processed,record_index,record_len,seed,algorithm,keygen_count,keygen_ns,sign_ns,"
       "ladder_sign_ns,verify_cold_ns,ladder_verify_ns,verify_warm_ns,signature_bytes,condensed_bytes,"
       "signed_ladder_bytes,public_key_bytes\n"
       "1,mtl,1,1,0,64,0,X,1,1,1,1,1,1,1,8004,76,7928,32\n")


def fake_run(root: Path, raw_files=("mtl_n1_t001.csv",), status="complete", listed=None,
             cache_files=("ttl0_s1.csv",)) -> Path:
    """A minimal run directory as run.main leaves it, with file hashes in the manifest."""
    (root / "raw").mkdir(parents=True)
    (root / "cache").mkdir()
    hashes = {}
    for name in raw_files:
        for f, text in ((name, CSV), (name[:-4] + ".meta.json", json.dumps({"timer_overhead_ns": 20}))):
            (root / "raw" / f).write_text(text)
            hashes[f"raw/{f}"] = manifest.sha256(root / "raw" / f)
    for name in cache_files:
        for f, text in ((name, "query\n0\n"), (name[:-4] + ".summary.json", json.dumps({"hits": 1}))):
            (root / "cache" / f).write_text(text)
            hashes[f"cache/{f}"] = manifest.sha256(root / "cache" / f)
    (root / "schedule.csv").write_text("round,position,arm,n,start_utc,seconds,status,error\n")
    hashes["schedule/schedule.csv"] = manifest.sha256(root / "schedule.csv")
    man = {"status": status, "run_id": "test"}
    if status in ("complete", "complete_with_failures"):
        man["outputs"] = {"raw": list(listed if listed is not None else raw_files), "cache": list(cache_files),
                          "schedule": ["schedule.csv"], "sha256": hashes}
    (root / "manifest.json").write_text(json.dumps(man))
    return root


def summary(run_dir: Path) -> dict:
    s = json.loads((run_dir / "summary.json").read_text())
    s.pop("generated_utc")
    return s


class RunDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_refuses_non_empty_directory(self):
        out = self.tmp / "final"
        out.mkdir()
        (out / "old.csv").write_text("left over\n")
        cfg = config.load()
        plan = self.tmp / "plan.json"
        plan.write_text(json.dumps({"config_sha256": planner.config_digest(cfg),
                                    "cells": [{"arm": "mtl", "n": 1, "records_per_trial": 1,
                                              "trials": 1}]}))
        with self.assertRaises(run.RunDirectoryError) as ctx:
            run.main(cfg, plan, out)
        self.assertIn("refusing to write", str(ctx.exception))
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["old.csv"], "nothing may be written")

    def test_refuses_plan_made_with_another_configuration(self):
        cfg = config.load()
        plan = self.tmp / "plan.json"
        plan.write_text(json.dumps({"config_sha256": "0" * 64, "cells": [
            {"arm": "mtl", "n": 1, "records_per_trial": 1, "trials": 1}]}))
        with self.assertRaises(SystemExit) as ctx:
            run.main(cfg, plan, self.tmp / "fresh")
        self.assertIn("different configuration", str(ctx.exception))
        self.assertFalse((self.tmp / "fresh").exists(), "nothing may be written")

    def test_config_digest_covers_every_benchmark_field(self):
        cfg = config.load()
        digest = planner.config_digest(cfg)
        changed = config.load()
        changed["workload"]["sizes"] = [10, 100]
        self.assertNotEqual(planner.config_digest(changed), digest)
        self.assertEqual(planner.config_digest({**cfg, "_path": "/elsewhere.toml"}), digest,
                         "the config path is not part of what is benchmarked")

    def test_accepts_new_or_empty_directory(self):
        run._prepare(self.tmp / "new")
        (self.tmp / "empty").mkdir()
        run._prepare(self.tmp / "empty")
        for d in ("new", "empty"):
            self.assertTrue((self.tmp / d / "raw").is_dir())

    def test_complete_run_loads(self):
        df, metas, man = analysis.load_run(fake_run(self.tmp / "ok"))
        self.assertEqual(len(df), 1)
        self.assertEqual(man["status"], "complete")

    def test_rejects_stale_file_from_earlier_run(self):
        r = fake_run(self.tmp / "stale")
        (r / "raw" / "plain_n10_t001.csv").write_text(CSV)
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("did not produce", str(ctx.exception))

    def test_rejects_missing_recorded_file(self):
        r = fake_run(self.tmp / "missing", listed=["mtl_n1_t001.csv", "mtl_n1_t002.csv"])
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("missing", str(ctx.exception))

    def test_rejects_unfinished_run(self):
        r = fake_run(self.tmp / "partial", status="running")
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("not a finished run", str(ctx.exception))

    def test_rejects_missing_metadata(self):
        r = fake_run(self.tmp / "nometa")
        (r / "raw" / "mtl_n1_t001.meta.json").unlink()
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("missing", str(ctx.exception))

    def test_rejects_unexpected_metadata(self):
        r = fake_run(self.tmp / "extrameta")
        (r / "raw" / "plain_n10_t001.meta.json").write_text("{}")
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("did not produce", str(ctx.exception))

    def test_rejects_modified_metadata(self):
        r = fake_run(self.tmp / "editedmeta")
        (r / "raw" / "mtl_n1_t001.meta.json").write_text(json.dumps({"timer_overhead_ns": 1}))
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("does not match the hash", str(ctx.exception))

    def test_rejects_modified_measurements(self):
        r = fake_run(self.tmp / "editedcsv")
        (r / "raw" / "mtl_n1_t001.csv").write_text(CSV.replace(",8004,", ",8000,"))
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("does not match the hash", str(ctx.exception))

    def test_rejects_modified_cache_summary(self):
        r = fake_run(self.tmp / "editedcache")
        (r / "cache" / "ttl0_s1.summary.json").write_text(json.dumps({"hits": 999}))
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("does not match the hash", str(ctx.exception))

    def test_rejects_manifest_without_hashes(self):
        r = fake_run(self.tmp / "nohashes")
        man = json.loads((r / "manifest.json").read_text())
        del man["outputs"]["sha256"]
        (r / "manifest.json").write_text(json.dumps(man))
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("no file hashes", str(ctx.exception))

    def test_rejects_modified_schedule(self):
        r = fake_run(self.tmp / "editschedule")
        (r / "schedule.csv").write_text("round,position,arm,n,start_utc,seconds,status,error\n1,1,mtl,1,x,0.1,ok,\n")
        with self.assertRaises(analysis.RunIntegrityError) as ctx:
            analysis.load_run(r)
        self.assertIn("schedule/schedule.csv", str(ctx.exception))

    def test_rejects_run_without_hashed_schedule(self):
        r = fake_run(self.tmp / "noschedule")
        man = json.loads((r / "manifest.json").read_text())
        del man["outputs"]["schedule"]
        (r / "manifest.json").write_text(json.dumps(man))
        with self.assertRaises(analysis.RunIntegrityError):
            analysis.load_run(r)

    def test_failed_invocations_are_not_reported_as_complete(self):
        r = fake_run(self.tmp / "partialok", status="complete_with_failures")
        man = analysis.load_run(r)[2]
        self.assertEqual(man["status"], "complete_with_failures")
        readme = self.tmp / "README.md"
        readme.write_text(f"before {report.README_START}old{report.README_END} after\n")
        (r / "report.md").write_text("## Summary\nsummary\n")
        with self.assertRaises(SystemExit) as ctx:
            report.update_readme(r, readme)
        self.assertIn("not a complete run", str(ctx.exception))
        self.assertIn("old", readme.read_text(), "README must be left untouched")

    def test_update_readme_preserves_utf8_content(self):
        r = self.tmp / "readme-run"
        r.mkdir()
        (r / "manifest.json").write_text(json.dumps({"status": "complete"}), encoding="utf-8")
        (r / "report.md").write_text("## Summary\n\nMeasured µs; response ≤ 1,232 B.\n\n## Configuration\n", encoding="utf-8")
        readme = self.tmp / "README.md"
        readme.write_text(f"Project — résumé {report.README_START}old{report.README_END} done\n", encoding="utf-8")
        report.update_readme(r, readme)
        content = readme.read_text(encoding="utf-8")
        self.assertIn("Project — résumé", content)
        self.assertIn("Measured µs; response ≤ 1,232 B.", content)
        self.assertIn("done", content)

    def test_report_uses_the_configuration_recorded_in_the_run(self):
        recorded = {"workload": {"sizes": [1]}, "dns": {"limits": [1232]}}
        got, drifted = analysis.run_config({"config": recorded, "config_path": "x.toml"},
                                           {"workload": {"sizes": [10]}, "dns": {"limits": [512]}})
        self.assertEqual(got["workload"]["sizes"], [1])
        self.assertEqual(got["dns"]["limits"], [1232])
        self.assertTrue(drifted)
        same, drifted = analysis.run_config({"config": recorded}, recorded)
        self.assertFalse(drifted)
        self.assertEqual(same["workload"]["sizes"], [1])

    def test_rejects_directory_without_manifest(self):
        (self.tmp / "loose" / "raw").mkdir(parents=True)
        (self.tmp / "loose" / "raw" / "mtl_n1_t001.csv").write_text(CSV)
        with self.assertRaises(analysis.RunIntegrityError):
            analysis.load_run(self.tmp / "loose")


@unittest.skipUnless((config.BIN / "bench").exists() and (config.BIN / "cachesim").exists(),
                     "harness not built (make harness)")
@unittest.skipIf(sys.platform == "win32", "the harness binaries are Linux executables; run this test in Docker")
class EndToEndTests(unittest.TestCase):
    """A tiny real run: fresh directory works, a second run into it is refused,
    and the first run's report is unchanged afterwards."""

    def test_second_run_into_same_directory_is_refused(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            cfg = config.load()
            cfg["workload"]["sizes"] = [2]
            cfg["cache"] = {"initial": 2, "queries": 20, "zipf": 1.0, "ttls": [0], "seeds": [1],
                            "growth_every": 0, "growth_size": 0}
            plan = tmp / "plan.json"
            plan.write_text(json.dumps({"config_sha256": planner.config_digest(cfg), "cells": [
                {"arm": "mtl", "n": 2, "records_per_trial": 2, "trials": 1, "extrapolated": False},
                {"arm": "plain", "n": 2, "records_per_trial": 1, "trials": 1, "extrapolated": True},
            ]}))
            out = tmp / "run"
            path, failures = run.main(cfg, plan, out)
            self.assertEqual(failures, [])
            man = json.loads((out / "manifest.json").read_text())
            self.assertEqual(man["status"], "complete")
            self.assertEqual(sorted(man["outputs"]["raw"]), ["mtl_n2_t001.csv", "plain_n2_t001.csv"])
            self.assertEqual(sorted(man["outputs"]["sha256"]), sorted(
                ["raw/mtl_n2_t001.csv", "raw/mtl_n2_t001.meta.json", "raw/plain_n2_t001.csv",
                 "raw/plain_n2_t001.meta.json", "cache/ttl0_s1.csv", "cache/ttl0_s1.summary.json",
                 "schedule/schedule.csv"]))
            self.assertEqual(man["trials"], {"planned": 2, "attempted": 2, "completed": 2, "failed": 0})
            self.assertEqual(man["cache_runs"], {"planned": 1, "completed": 1})
            report.build(cfg, out)
            before = summary(out)

            meta = out / "raw" / "mtl_n2_t001.meta.json"
            original = meta.read_text()
            meta.write_text(original.replace('"program": "bench"', '"program": "edited"'))
            with self.assertRaises(analysis.RunIntegrityError):
                report.build(cfg, out)
            meta.write_text(original)

            with self.assertRaises(run.RunDirectoryError):
                run.main(cfg, plan, out)
            self.assertEqual(sorted(json.loads((out / "manifest.json").read_text())["outputs"]["raw"]),
                             ["mtl_n2_t001.csv", "plain_n2_t001.csv"])
            report.build(cfg, out)
            self.assertEqual(summary(out), before, "the refused run must leave the first run untouched")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
