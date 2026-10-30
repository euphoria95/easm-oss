#!/usr/bin/env python3
"""
Tests for the subfinder / cdncheck / waf-detector stages (run.sh `subfinder`,
`cdn`, `waf` stages + normalize.py ingest + detect_cdn.py voting).

No network access: the three binaries are replaced by fake scripts on PATH
that emit the real tools' JSON schemas.

Run: python3 scripts/test_recon_tools.py
Exit 0 = all tests passed.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent
REPO = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

from detect_cdn import CDNDetector, normalize_provider  # noqa: E402
from normalize import AssetStore  # noqa: E402


def cdncheck_rec(inp, ip="203.0.113.1", cdn=None, cloud=None, waf=None) -> dict:
    rec = {"input": inp, "ip": ip}
    if cdn:
        rec.update(cdn=True, cdn_name=cdn)
    if cloud:
        rec.update(cloud=True, cloud_name=cloud)
    if waf:
        rec.update(waf=True, waf_name=waf)
    return rec


def waf_rec(url, waf=None, waf_conf=0.9, cdn=None, cdn_conf=0.8, error=None) -> dict:
    rec = {
        "url": url,
        "detected_waf": {"name": waf, "confidence": waf_conf} if waf else None,
        "detected_cdn": {"name": cdn, "confidence": cdn_conf} if cdn else None,
        "provider_scores": {}, "evidence_map": {}, "detection_time_ms": 5,
        "metadata": {"timestamp": "2026-10-30T00:00:00Z", "version": "0.1.0", "user_agent": "x"},
    }
    if error:
        rec["error"] = error
    return rec


def store_with(*hosts) -> AssetStore:
    store = AssetStore(scan_id="t")
    store.ingest_dns([{"host": h, "a": ["203.0.113.1"]} for h in hosts])
    return store


class SubfinderTagging(unittest.TestCase):
    def test_tags_existing_assets_only(self):
        store = store_with("www.example.com")
        self.assertEqual(store.tag_subfinder_discovered(["WWW.example.com", "ghost.example.com"]), 1)
        self.assertIn("subfinder", store.assets["www.example.com"]["source"])
        self.assertNotIn("ghost.example.com", store.assets)


class CdncheckIngest(unittest.TestCase):
    def test_classification_fields(self):
        store = store_with("a.example.com")
        store.ingest_cdncheck([cdncheck_rec("A.example.com", cdn="fastly", cloud="aws")])
        net = store.assets["a.example.com"]["network"]
        self.assertEqual(net["cdncheck"], {"ip": "203.0.113.1", "cdn": "fastly", "cloud": "aws", "waf": None})
        self.assertIsNone(net["waf"])
        self.assertIn("cdncheck", store.assets["a.example.com"]["source"])

    def test_waf_from_ip_range(self):
        store = store_with("a.example.com")
        store.ingest_cdncheck([cdncheck_rec("a.example.com", waf="cloudflare")])
        waf = store.assets["a.example.com"]["network"]["waf"]
        self.assertEqual((waf["provider"], waf["confidence"], waf["sources"]), ("cloudflare", 0.6, ["cdncheck"]))
        self.assertIn("waf", store.assets["a.example.com"]["tags"])

    def test_ip_input_creates_ip_asset(self):
        store = AssetStore(scan_id="t")
        store.ingest_cdncheck([cdncheck_rec("198.51.100.7", ip="198.51.100.7", cloud="azure")])
        self.assertEqual(store.assets["198.51.100.7"]["network"]["cdncheck"]["cloud"], "azure")


class WafIngest(unittest.TestCase):
    def test_highest_confidence_origin_wins(self):
        store = store_with("a.example.com")
        store.ingest_waf([
            waf_rec("https://a.example.com/", waf="Akamai", waf_conf=0.5),
            waf_rec("http://a.example.com:8080/", waf="Imperva", waf_conf=0.95),
            waf_rec("https://a.example.com:8443/", waf="F5", waf_conf=0.7),
        ])
        waf = store.assets["a.example.com"]["network"]["waf"]
        self.assertEqual((waf["provider"], waf["confidence"]), ("imperva", 0.95))
        self.assertEqual(waf["url"], "http://a.example.com:8080/")

    def test_corroborates_cdncheck_same_provider(self):
        store = store_with("a.example.com")
        store.ingest_cdncheck([cdncheck_rec("a.example.com", waf="cloudflare")])
        store.ingest_waf([waf_rec("https://a.example.com/", waf="CloudFlare", waf_conf=0.92)])
        waf = store.assets["a.example.com"]["network"]["waf"]
        self.assertEqual(waf["sources"], ["cdncheck", "waf-detector"])
        self.assertEqual(waf["confidence"], 0.92)

    def test_fingerprint_overrides_ip_range_only_verdict(self):
        store = store_with("a.example.com")
        store.ingest_cdncheck([cdncheck_rec("a.example.com", waf="incapsula")])
        store.ingest_waf([waf_rec("https://a.example.com/", waf="F5", waf_conf=0.4)])
        self.assertEqual(store.assets["a.example.com"]["network"]["waf"]["provider"], "f5")

    def test_errors_and_empty_results_skipped(self):
        store = store_with("a.example.com")
        store.ingest_waf([
            waf_rec("https://a.example.com/", waf="Akamai", error="timeout"),
            waf_rec("https://a.example.com:8443/"),
            {"url": ""},
        ])
        self.assertIsNone(store.assets["a.example.com"]["network"]["waf"])
        self.assertNotIn("waf", store.assets["a.example.com"]["tags"])

    def test_cdn_verdict_stashed_for_detector(self):
        store = store_with("a.example.com")
        store.ingest_waf([waf_rec("https://a.example.com/", cdn="Fastly", cdn_conf=0.7)])
        self.assertEqual(store.assets["a.example.com"]["network"]["waf_detector_cdn"],
                         {"provider": "Fastly", "confidence": 0.7})


class CdnVoting(unittest.TestCase):
    def test_provider_name_mapping(self):
        self.assertEqual(normalize_provider("Incapsula"), "imperva")
        self.assertEqual(normalize_provider("amazon"), "cloudfront")
        self.assertEqual(normalize_provider("CloudFlare"), "cloudflare")
        self.assertEqual(normalize_provider("Some Vendor"), "some_vendor")
        self.assertIsNone(normalize_provider(""))

    def test_cdncheck_and_waf_detector_add_signal_types(self):
        store = store_with("a.example.com")
        store.ingest_cdncheck([cdncheck_rec("a.example.com", cdn="fastly")])
        store.ingest_waf([waf_rec("https://a.example.com/", cdn="Fastly")])
        result = CDNDetector().detect(store.assets["a.example.com"])
        self.assertEqual(result["provider"], "fastly")
        self.assertEqual(sorted(result["signals"]), ["cdncheck:fastly", "wafdetector:fastly"])
        self.assertEqual(result["confidence"], 0.7)

    def test_cdncheck_waf_category_counts_as_cdn_for_cloudflare(self):
        store = store_with("a.example.com")
        store.ingest_cdncheck([cdncheck_rec("a.example.com", waf="cloudflare")])
        self.assertEqual(CDNDetector().detect(store.assets["a.example.com"])["provider"], "cloudflare")

    def test_cdncheck_cloud_only_is_not_cdn(self):
        store = store_with("a.example.com")
        store.ingest_cdncheck([cdncheck_rec("a.example.com", cloud="aws")])
        self.assertIsNone(CDNDetector().detect(store.assets["a.example.com"]))


class NormalizeCli(unittest.TestCase):
    def test_flags_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "dns.jsonl").write_text(json.dumps({"host": "www.example.com", "a": ["203.0.113.1"]}) + "\n")
            (tmp / "sf.txt").write_text("www.example.com\n")
            (tmp / "cdn.jsonl").write_text(json.dumps(cdncheck_rec("www.example.com", waf="cloudflare")) + "\n")
            (tmp / "waf.jsonl").write_text(json.dumps(waf_rec("https://www.example.com/", waf="CloudFlare")) + "\n")
            r = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "normalize.py"), "--dns", str(tmp / "dns.jsonl"),
                 "--subfinder", str(tmp / "sf.txt"), "--cdncheck", str(tmp / "cdn.jsonl"),
                 "--waf", str(tmp / "waf.jsonl"), "--output", str(tmp / "assets.jsonl")],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-500:])
            asset = json.loads((tmp / "assets.jsonl").read_text().splitlines()[0])
            self.assertTrue({"subfinder", "cdncheck", "waf-detector"} <= set(asset["source"]))
            self.assertEqual(asset["network"]["waf"]["provider"], "cloudflare")
            self.assertEqual(asset["network"]["cdn"], "cloudflare")
            self.assertIn("behind_waf: 1", r.stderr)


FAKE_SUBFINDER = r"""#!/usr/bin/env bash
echo "$@" > "$FAKE_LOG_DIR/subfinder.args"
for h in www.example.com NEW.example.com api.example.com. notexample.com evil.org; do
  printf '{"host":"%s","input":"example.com","sources":["fake"]}\n' "$h"
done
"""

FAKE_CDNCHECK = r"""#!/usr/bin/env bash
if [[ "$1" == "-h" ]]; then echo "   -t, -threads int  number of concurrent threads"; exit 0; fi
echo "$@" > "$FAKE_LOG_DIR/cdncheck.args"
while [[ $# -gt 0 ]]; do [[ "$1" == "-i" ]] && in="$2"; shift; done
while read -r h; do
  printf '{"input":"%s","ip":"203.0.113.1","waf":true,"waf_name":"cloudflare"}\n' "$h"
done < "$in"
"""

FAKE_WAF = r"""#!/usr/bin/env bash
echo "$@" >> "$FAKE_LOG_DIR/waf.args"
while read -r u; do
  printf '{"url":"%s/","detected_waf":{"name":"CloudFlare","confidence":0.9},"detected_cdn":null}\n' "$u"
done
"""


# naabu omits "host" when the input is a bare IP — only "ip" is set
FAKE_NAABU = r"""#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && out="$2"; shift; done
cat > "$out" <<'JSON'
{"host":"www.example.com","ip":"203.0.113.9","port":443,"protocol":"tcp","tls":false}
{"ip":"198.51.100.7","port":80,"protocol":"tcp","tls":false}
{"ip":"198.51.100.7","port":22,"protocol":"tcp","tls":false}
JSON
"""


class RunShStages(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        bindir = self.tmp / "bin"
        bindir.mkdir()
        for name, body in (("subfinder", FAKE_SUBFINDER), ("cdncheck", FAKE_CDNCHECK), ("waf-detect", FAKE_WAF),
                           ("naabu", FAKE_NAABU)):
            f = bindir / name
            f.write_text(body)
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        self.out = self.tmp / "out"
        self.out.mkdir()
        inp = self.tmp / "in.txt"
        inp.write_text("www.example.com\n")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("ROOT_DOMAINS")}
        self.env.update({
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "FAKE_LOG_DIR": str(self.tmp),
            "INPUT_SUBDOMAINS_OVERRIDE": os.path.relpath(inp, REPO),
            "OUTPUT_DIR_OVERRIDE": os.path.relpath(self.out, REPO),
            "LOG_DIR_OVERRIDE": os.path.relpath(self.tmp / "logs", REPO),
            "CACHE_DIR_OVERRIDE": os.path.relpath(self.tmp / "cache", REPO),
            "SCREENSHOT_DIR_OVERRIDE": os.path.relpath(self.tmp / "shots", REPO),
        })

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, *args, **env):
        e = dict(self.env, **env)
        r = subprocess.run(["bash", str(REPO / "run.sh"), *args], capture_output=True, text=True, cwd=REPO, env=e)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
        return r.stdout + r.stderr

    def test_stage_order(self):
        out = self._run("--dry-run")
        stages = [l.split(": ")[1].strip() for l in out.splitlines() if "Would run:" in l]
        self.assertEqual(stages[:6], ["subfinder", "ct", "dns", "asn", "rdns", "cdn"])
        self.assertLess(stages.index("http"), stages.index("waf"))
        self.assertLess(stages.index("waf"), stages.index("tls"))

    def test_livecheck_includes_cdn_only(self):
        out = self._run("--dry-run", "--mode", "livecheck")
        stages = [l.split(": ")[1].strip() for l in out.splitlines() if "Would run:" in l]
        self.assertIn("cdn", stages)
        self.assertNotIn("subfinder", stages)
        self.assertNotIn("waf", stages)

    def test_subfinder_skipped_without_root_domains(self):
        out = self._run("--stage", "subfinder")
        self.assertIn("ROOT_DOMAINS not set — skipping subfinder", out)
        self.assertFalse((self.tmp / "subfinder.args").exists())

    def test_subfinder_scope_filter_and_merge(self):
        out = self._run("--stage", "subfinder", ROOT_DOMAINS_OVERRIDE="Example.com")
        self.assertEqual((self.out / "subfinder_subdomains.txt").read_text().split(),
                         ["api.example.com", "new.example.com", "www.example.com"])
        self.assertEqual((self.out / "targets.txt").read_text().split(),
                         ["api.example.com", "new.example.com", "www.example.com"])
        self.assertIn("added=2", out)
        args = (self.tmp / "subfinder.args").read_text()
        self.assertIn("-es crtsh", args)
        self.assertNotIn("-pc", args)  # no provider config committed

    def test_cdn_stage(self):
        (self.out / "live_hosts.txt").write_text("www.example.com\n203.0.113.9\n")
        out = self._run("--stage", "cdn")
        lines = (self.out / "cdncheck.jsonl").read_text().splitlines()
        self.assertEqual([json.loads(l)["input"] for l in lines], ["www.example.com", "203.0.113.9"])
        self.assertIn("cdn_or_waf=2", out)
        args = (self.tmp / "cdncheck.args").read_text()
        self.assertIn("-t 50", args)
        self.assertNotIn("resolvers.txt", args)  # -r gets a comma list, not the file path
        self.assertRegex(args, r"-r \d+\.\d+\.\d+\.\d+,")

    def test_waf_stage_dedups_origins_and_stays_passive(self):
        httpx = [
            {"url": "https://www.example.com:443/login?x=1"},
            {"url": "https://www.example.com:443/"},
            {"url": "http://www.example.com:8080"},
            {"input": "no-url"},
        ]
        (self.out / "httpx.jsonl").write_text("".join(json.dumps(r) + "\n" for r in httpx))
        out = self._run("--stage", "waf", WAF_BATCH_SIZE="1", WAF_WORKERS="2")
        urls = sorted(json.loads(l)["url"] for l in (self.out / "waf.jsonl").read_text().splitlines())
        self.assertEqual(urls, ["http://www.example.com:8080/", "https://www.example.com:443/"])
        self.assertIn("waf_detected=2", out)
        for line in (self.tmp / "waf.args").read_text().splitlines():
            self.assertEqual(line.strip(), "scan --stdin --ndjson")
        self.assertFalse((self.out / "_waf_shards").exists())

    def test_ports_web_targets_fall_back_to_ip(self):
        (self.out / "live_hosts.txt").write_text("www.example.com\n198.51.100.7\n")
        out = self._run("--stage", "ports")
        self.assertEqual((self.out / "web_targets.txt").read_text().split(),
                         ["198.51.100.7:80", "www.example.com:443"])
        self.assertIn("web_targets=2", out)

    def test_waf_skipped_without_http_data(self):
        out = self._run("--stage", "waf")
        self.assertIn("No HTTP origins — skipping WAF detection", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
