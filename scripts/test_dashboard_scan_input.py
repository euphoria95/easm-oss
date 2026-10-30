#!/usr/bin/env python3
"""
Tests for the dashboard's New Scan input handling (dashboard/app.py):
targets-list parsing and the optional CMDB export upload. No pipeline runs —
the background thread is patched out.

Run: python3 scripts/test_dashboard_scan_input.py
Exit 0 = all tests passed.
"""

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).parent.parent

try:
    import duckdb  # noqa: F401
    import fastapi  # noqa: F401
    sys.path.insert(0, str(REPO))
    from dashboard import app as dash
except ImportError:
    dash = None


class _Request:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


@unittest.skipUnless(dash, "fastapi / duckdb not installed")
class ParseTargets(unittest.TestCase):
    def test_formats(self):
        text = """
            # header comment
            App.Example.com
            https://shop.example.com:8443/login?x=1   # inline comment
            api.example.com, cdn.example.com;mail.example.com
            *.wild.example.com
            "quoted.example.com"
            93.184.216.10
            93.184.216.0/28
            [2001:db8::1]:443
            2001:db8::2
            _dmarc.example.com
            app.example.com
            not_a_host!  http://  ..
        """
        targets, rejected = dash._parse_targets(text)
        self.assertEqual(targets, [
            "app.example.com", "shop.example.com", "api.example.com", "cdn.example.com",
            "mail.example.com", "wild.example.com", "quoted.example.com", "93.184.216.10",
            "93.184.216.0/28", "2001:db8::1", "2001:db8::2", "_dmarc.example.com",
        ])
        self.assertEqual(rejected, ["not_a_host!", "http://", ".."])

    def test_cidr_normalized(self):
        self.assertEqual(dash._parse_targets("93.184.216.7/28")[0], ["93.184.216.0/28"])

    def test_domain_with_path_is_not_cidr(self):
        self.assertEqual(dash._parse_targets("example.com/path")[0], ["example.com"])


@unittest.skipUnless(dash, "fastapi / duckdb not installed")
class CmdbCsv(unittest.TestCase):
    def test_header_lowercased_and_rows_counted(self):
        text, rows = dash._normalize_cmdb_csv("﻿CI_ID, FQDN ,Owner\nCI1,a.example.com,ops\n\n,,\nCI2,b.example.com,\n")
        self.assertEqual(rows, 2)
        self.assertEqual(text.splitlines()[0], "ci_id,fqdn,owner")

    def test_rejects_missing_host_column(self):
        with self.assertRaises(dash.HTTPException) as ctx:
            dash._normalize_cmdb_csv("ci_id,ip\nCI1,1.2.3.4\n")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("found: ci_id, ip", ctx.exception.detail)

    def test_rejects_header_only(self):
        with self.assertRaises(dash.HTTPException):
            dash._normalize_cmdb_csv("hostname,owner\n")


@unittest.skipUnless(dash, "fastapi / duckdb not installed")
class CreateScan(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.input_dir = root / "data" / "input"
        self.threads = []
        patches = [
            mock.patch.object(dash, "PROJECT_ROOT", root),
            mock.patch.object(dash, "INPUT_DIR", self.input_dir),
            mock.patch.object(dash, "SCAN_STATE_FILE", root / "data" / ".scan_state.json"),
            mock.patch.object(dash.threading, "Thread", side_effect=self._thread),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)

    def _thread(self, target, args, daemon):
        self.threads.append(args)
        return mock.Mock()

    def _create(self, **body):
        return asyncio.run(dash.create_scan(_Request(body)))

    def test_targets_and_cmdb_written(self):
        r = self._create(subdomains="b.example.com\nhttps://a.example.com/\njunk!\n",
                         cmdb_csv="FQDN,ci_id\na.example.com,CI1\n", mode="livecheck")
        self.assertEqual((r["subdomain_count"], r["rejected_count"], r["cmdb_rows"]), (2, 1, 1))
        self.assertEqual(r["rejected_sample"], ["junk!"])
        sid = r["scan_id"]
        self.assertEqual((self.input_dir / f"scan_{sid}.txt").read_text(), "a.example.com\nb.example.com\n")
        self.assertEqual((self.input_dir / f"cmdb_{sid}.csv").read_text(), "fqdn,ci_id\na.example.com,CI1\n")
        args = self.threads[0]
        self.assertEqual(args[3], "livecheck")
        self.assertEqual((args[5], args[6]), (str(self.input_dir / f"cmdb_{sid}.csv"), 1))

    def test_without_cmdb(self):
        r = self._create(subdomains="a.example.com")
        self.assertIsNone(r["cmdb_rows"])
        self.assertEqual(self.threads[0][5], "")
        self.assertEqual(list(self.input_dir.glob("cmdb_*.csv")), [])

    def test_bad_cmdb_rejected_before_anything_runs(self):
        with self.assertRaises(dash.HTTPException) as ctx:
            self._create(subdomains="a.example.com", cmdb_csv="id,ip\n1,2\n")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(self.threads, [])

    def test_only_junk_is_400(self):
        with self.assertRaises(dash.HTTPException) as ctx:
            self._create(subdomains="!!! ???")
        self.assertIn("No valid targets", ctx.exception.detail)

    def test_size_limit(self):
        with mock.patch.object(dash, "_MAX_INPUT_BYTES", 10):
            with self.assertRaises(dash.HTTPException) as ctx:
                self._create(subdomains="a.example.com\nb.example.com\n")
        self.assertEqual(ctx.exception.status_code, 413)


@unittest.skipUnless(dash, "fastapi / duckdb not installed")
class RunPipelineEnv(unittest.TestCase):
    def test_cmdb_override_passed_to_run_sh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data" / "input").mkdir(parents=True)
            with mock.patch.object(dash, "PROJECT_ROOT", root), \
                 mock.patch.object(dash, "SCAN_STATE_FILE", root / "data" / ".scan_state.json"), \
                 mock.patch.object(dash.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
                dash._run_pipeline("20261030_120000", str(root / "data/input/scan_x.txt"),
                                   cmdb_file=str(root / "data/input/cmdb_x.csv"), cmdb_rows=3)
                env = run.call_args.kwargs["env"]
                self.assertEqual(env["CMDB_EXPORT_OVERRIDE"], "data/input/cmdb_x.csv")
                self.assertEqual(env["INPUT_SUBDOMAINS_OVERRIDE"], "data/input/scan_x.txt")
                self.assertEqual(dash._read_scan_state()["cmdb_rows"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
