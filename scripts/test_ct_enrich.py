#!/usr/bin/env python3
"""
Tests for the CT-log enrichment stage (scripts/ct_enrich.py + run.sh `ct` stage +
normalize.py --ct tagging). No network access: crt.sh responses are faked.

Run: python3 scripts/test_ct_enrich.py
Exit 0 = all tests passed.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

SCRIPTS_DIR = Path(__file__).parent
REPO = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

import ct_enrich  # noqa: E402


def rec(name_value: str, common_name: str = "") -> dict:
    return {"name_value": name_value, "common_name": common_name}


class ParseDomains(unittest.TestCase):
    def test_splits_normalizes_and_dedups(self):
        self.assertEqual(
            ct_enrich.parse_domains("Example.com, example.org  *.example.com\nexample.org."),
            ["example.com", "example.org"],
        )

    def test_rejects_invalid(self):
        self.assertEqual(ct_enrich.parse_domains("bad_domain!, nodots, ok.example.com"), ["ok.example.com"])

    def test_empty(self):
        self.assertEqual(ct_enrich.parse_domains(" , "), [])


class ExtractNames(unittest.TestCase):
    def test_keeps_root_and_subdomains(self):
        names = ct_enrich.extract_names(
            [rec("example.com\nwww.example.com", "api.example.com")], "example.com")
        self.assertEqual(names, {"example.com", "www.example.com", "api.example.com"})

    def test_strips_wildcards_and_lowercases(self):
        names = ct_enrich.extract_names([rec("*.Dev.Example.com")], "example.com")
        self.assertEqual(names, {"dev.example.com"})

    def test_drops_out_of_scope_sans(self):
        # A shared cert carries third-party SANs, a lookalike suffix, and an email.
        names = ct_enrich.extract_names(
            [rec("a.example.com\nother.org\nnotexample.com\nexample.com.evil.net\nadmin@example.com")],
            "example.com")
        self.assertEqual(names, {"a.example.com"})

    def test_drops_embedded_wildcards_and_junk(self):
        names = ct_enrich.extract_names(
            [rec("a.*.example.com\n\n  \nok.example.com."), "garbage", {"name_value": None}],
            "example.com")
        self.assertEqual(names, {"ok.example.com"})


class Fetch(unittest.TestCase):
    def _resp(self, body: bytes):
        r = mock.MagicMock()
        r.read.return_value = body
        r.__enter__.return_value = r
        return r

    def test_retries_then_succeeds(self):
        calls = [urllib.error.URLError("502"), self._resp(b"[]")]
        with mock.patch("urllib.request.urlopen", side_effect=calls) as m, \
                mock.patch("time.sleep") as sleep:
            self.assertEqual(ct_enrich.fetch_crtsh("example.com", 5, 3, "ua"), [])
        self.assertEqual(m.call_count, 2)
        sleep.assert_called_once()

    def test_truncated_json_is_retried_and_finally_raises(self):
        with mock.patch("urllib.request.urlopen", return_value=self._resp(b'[{"name_value": "a')) as m, \
                mock.patch("time.sleep"):
            with self.assertRaises(RuntimeError):
                ct_enrich.fetch_crtsh("example.com", 5, 3, "ua")
        self.assertEqual(m.call_count, 3)

    def test_non_list_response_rejected(self):
        with mock.patch("urllib.request.urlopen", return_value=self._resp(b'{"error": "x"}')), \
                mock.patch("time.sleep"):
            with self.assertRaises(RuntimeError):
                ct_enrich.fetch_crtsh("example.com", 5, 2, "ua")

    def test_query_is_percent_encoded_wildcard(self):
        with mock.patch("urllib.request.urlopen", return_value=self._resp(b"[]")) as m:
            ct_enrich.fetch_crtsh("example.com", 5, 1, "my-ua")
        req = m.call_args[0][0]
        self.assertIn("q=%25.example.com", req.full_url)
        self.assertEqual(req.get_header("User-agent"), "my-ua")


class Main(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.out = self.dir / "ct.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, domains, fetch, existing=None):
        argv = ["--domains", domains, "--output", str(self.out), "--delay", "0"]
        if existing:
            argv += ["--existing", str(existing)]
        return ct_enrich.main(argv, fetch=fetch)

    def test_writes_sorted_unique_in_scope_names(self):
        def fetch(domain, *_):
            return [rec(f"b.{domain}\na.{domain}\nb.{domain}")]
        self.assertEqual(self.run_main("example.com,example.org", fetch), 0)
        self.assertEqual(self.out.read_text().split(), [
            "a.example.com", "a.example.org", "b.example.com", "b.example.org"])

    def test_partial_failure_still_succeeds(self):
        def fetch(domain, *_):
            if domain == "bad.com":
                raise RuntimeError("502")
            return [rec(f"www.{domain}")]
        self.assertEqual(self.run_main("bad.com,good.com", fetch), 0)
        self.assertEqual(self.out.read_text().split(), ["www.good.com"])

    def test_total_failure_exits_1_and_writes_empty_file(self):
        def fetch(*_):
            raise RuntimeError("down")
        self.assertEqual(self.run_main("example.com", fetch), 1)
        self.assertEqual(self.out.read_text(), "")

    def test_no_valid_domains_is_a_noop(self):
        def fetch(*_):
            self.fail("must not query crt.sh")
        self.assertEqual(self.run_main("not_a_domain!", fetch), 0)
        self.assertEqual(self.out.read_text(), "")

    def test_reports_new_vs_known(self):
        existing = self.dir / "targets.txt"
        existing.write_text("www.example.com\n")
        err = []
        with mock.patch.object(ct_enrich, "log", err.append):
            self.run_main("example.com", lambda d, *_: [rec("www.example.com\napi.example.com")], existing)
        self.assertIn("found=2 new=1 known=1", "\n".join(err))
        # output holds everything CT saw, known names included (used for source tagging)
        self.assertEqual(self.out.read_text().split(), ["api.example.com", "www.example.com"])


class NormalizeTagging(unittest.TestCase):
    def test_tags_existing_assets_only(self):
        from normalize import AssetStore
        store = AssetStore(scan_id="t")
        store.ingest_dns([{"host": "www.example.com", "a": ["203.0.113.1"]}])
        tagged = store.tag_ct_discovered(["www.example.com", "ghost.example.com"])
        self.assertEqual(tagged, 1)
        self.assertIn("crt.sh", store.assets["www.example.com"]["source"])
        self.assertNotIn("ghost.example.com", store.assets)  # never invented

    def test_cli_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "dns.jsonl").write_text(json.dumps({"host": "www.example.com", "a": ["203.0.113.1"]}) + "\n")
            (tmp / "ct.txt").write_text("www.example.com\n")
            r = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "normalize.py"), "--dns", str(tmp / "dns.jsonl"),
                 "--ct", str(tmp / "ct.txt"), "--output", str(tmp / "assets.jsonl")],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-500:])
            asset = json.loads((tmp / "assets.jsonl").read_text().splitlines()[0])
            self.assertIn("crt.sh", asset["source"])


class RunShWiring(unittest.TestCase):
    def _run(self, *args, env=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith("ROOT_DOMAINS")}
        e.update(env or {})
        return subprocess.run(["bash", str(REPO / "run.sh"), *args],
                              capture_output=True, text=True, cwd=REPO, env=e)

    def test_ct_runs_before_dns(self):
        r = self._run("--dry-run")
        stages = [l.split(": ")[1].strip() for l in (r.stdout + r.stderr).splitlines() if "Would run:" in l]
        self.assertEqual(stages[:3], ["subfinder", "ct", "dns"])

    def test_ct_stage_skipped_without_root_domains_and_in_livecheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "in.txt"
            inp.write_text("www.example.com\n")
            env = {
                "INPUT_SUBDOMAINS_OVERRIDE": os.path.relpath(inp, REPO),
                "OUTPUT_DIR_OVERRIDE": os.path.relpath(Path(tmp) / "out", REPO),
                "LOG_DIR_OVERRIDE": os.path.relpath(Path(tmp) / "logs", REPO),
                "CACHE_DIR_OVERRIDE": os.path.relpath(Path(tmp) / "cache", REPO),
                "SCREENSHOT_DIR_OVERRIDE": os.path.relpath(Path(tmp) / "shots", REPO),
            }
            r = self._run("--stage", "ct", env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("ROOT_DOMAINS not set — skipping CT enrichment", r.stdout + r.stderr)
            self.assertFalse((Path(tmp) / "out" / "ct_subdomains.txt").exists())

    def test_ct_stage_wiring_with_unusable_domain(self):
        """ROOT_DOMAINS set but invalid → stage runs, adds nothing, targets untouched."""
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "in.txt"
            inp.write_text("www.example.com\n")
            env = {
                "ROOT_DOMAINS_OVERRIDE": "not_a_domain!",
                "INPUT_SUBDOMAINS_OVERRIDE": os.path.relpath(inp, REPO),
                "OUTPUT_DIR_OVERRIDE": os.path.relpath(Path(tmp) / "out", REPO),
                "LOG_DIR_OVERRIDE": os.path.relpath(Path(tmp) / "logs", REPO),
                "CACHE_DIR_OVERRIDE": os.path.relpath(Path(tmp) / "cache", REPO),
                "SCREENSHOT_DIR_OVERRIDE": os.path.relpath(Path(tmp) / "shots", REPO),
            }
            r = self._run("--stage", "ct", env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("CT enrichment complete | input=1 ct_added=0 total=1", r.stdout + r.stderr)
            self.assertEqual((Path(tmp) / "out" / "targets.txt").read_text().split(), ["www.example.com"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
