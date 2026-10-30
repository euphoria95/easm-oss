#!/usr/bin/env python3
"""
Tests for Tenable VM / WAS scope routing (tenable_scope.py, cmdb_scope_export.py
routing mode, load_duckdb.py v_tenable_* views, run.sh `scope` stage).

Unit tests walk every row of the routing matrix in TENABLE_SCOPE_PIPELINE.MD;
integration tests run normalize → DuckDB load → scope export → views. No network access.

Run: python3 scripts/test_tenable_scope.py
Exit 0 = all tests passed.
"""

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent
REPO = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

import orjson  # noqa: E402

from tenable_scope import (  # noqa: E402
    ScopeConfig, analyze_web, parse_owned_asns, parse_owned_networks, route_assets,
)

IP = "93.184.216.10"


def web(url, status=200, ct="text/html", title="App", final_url="", port=None):
    if port is None:
        port = 443 if url.startswith("https") else 80
    return {"url": url, "status_code": status, "content_type": ct, "title": title,
            "final_url": final_url, "port": port}


def asset(fqdn, ips=(IP,), ports=(443,), webs=None, in_cmdb=False, **network):
    """Minimal normalize.py-shaped asset; extra kwargs land in network."""
    if webs is None:
        webs = [web(f"https://{fqdn}")]
    rec = {
        "fqdn": fqdn,
        "scan_id": "t",
        "dns": {"a": list(ips), "cname_chain": network.pop("cnames", [])},
        "network": {"asn": network.pop("asn", {"number": 64500, "org": "EXAMPLE-NET"}),
                    "open_ports": [{"port": p, "protocol": "tcp"} for p in ports]},
        "web": webs,
        "findings": network.pop("findings", []),
        "cloud": {"endpoints": [{"provider": "x", "service": s} for s in network.pop("cloud", [])]},
        "cmdb": {"in_cmdb": in_cmdb},
    }
    if "ai_protocols" in network:
        rec["ai_protocols"] = network.pop("ai_protocols")
    rec["network"].update(network)
    return rec


def _has_xlsxwriter() -> bool:
    try:
        import xlsxwriter  # noqa: F401
        return True
    except ImportError:
        return False


def route(*assets, **cfg):
    rows, ips = route_assets(list(assets), ScopeConfig(**cfg))
    return {r["fqdn"]: r for r in rows}, {r["target_ip"]: r for r in ips}


class RoutingMatrix(unittest.TestCase):
    """One test per row of the routing matrix."""

    def test_1_direct_ip(self):
        a, ips = route(asset("app.example.com", ports=(22, 443)))
        r = a["app.example.com"]
        self.assertEqual((r["category"], r["vm_action"], r["was_profile"]), ("direct", "include", "standard"))
        self.assertEqual(r["was_urls"], ["https://app.example.com"])
        self.assertEqual(ips[IP]["action"], "include")
        self.assertEqual(ips[IP]["ports"], [22, 443])
        self.assertEqual(ips[IP]["vm_category"], "direct")

    def test_2_cdn_excluded_from_vm_but_web_app_goes_to_was(self):
        a, ips = route(asset("cdn.example.com",
                             cdn_detection={"provider": "cloudfront", "confidence": 0.35, "signals": ["cname:x"]}))
        r = a["cdn.example.com"]
        self.assertEqual((r["category"], r["vm_action"]), ("cdn", "exclude"))
        self.assertEqual(r["vm_reasons"], ["cdn:cloudfront"])
        self.assertEqual((r["was_action"], r["was_profile"]), ("include", "standard"))
        self.assertEqual(ips[IP]["action"], "exclude")

    def test_2_cdn_threshold_is_configurable(self):
        a, _ = route(asset("cdn.example.com", cdn_detection={"provider": "cloudfront", "confidence": 0.35}),
                     cdn_min_confidence=0.5)
        self.assertEqual(a["cdn.example.com"]["vm_action"], "include")

    def test_2_cdn_edge_asn_excluded(self):
        a, _ = route(asset("x.example.com", asn={"number": 13335, "org": "CLOUDFLARENET"}))
        self.assertEqual(a["x.example.com"]["vm_reasons"], ["cdn:cloudflare"])

    def test_2_iaas_on_cdn_vendor_asn_not_edge(self):
        a, _ = route(asset("vm.example.com", asn={"number": 63949, "org": "AKAMAI-LINODE-AP Akamai Connected Cloud"}))
        self.assertEqual(a["vm.example.com"]["vm_action"], "include")

    def test_3_waf_excluded_from_vm_and_routed_to_waf_profile(self):
        a, ips = route(asset("waf.example.com", waf={"detected": True, "provider": "f5", "confidence": 0.9}))
        r = a["waf.example.com"]
        self.assertEqual((r["category"], r["vm_action"], r["was_profile"]), ("waf", "exclude", "waf"))
        self.assertEqual(ips[IP]["reasons"], ["waf:f5"])

    def test_3_low_confidence_waf_ignored(self):
        a, _ = route(asset("w.example.com", waf={"provider": "f5", "confidence": 0.3}))
        self.assertEqual((a["w.example.com"]["vm_action"], a["w.example.com"]["was_profile"]), ("include", "standard"))

    def test_4_shared_hosting_provider_vm_excluded_was_included(self):
        a, _ = route(asset("blog.example.com",
                           shared_hosting={"detected": True, "signals": ["asn:godaddy", "ip_density:40"]}))
        r = a["blog.example.com"]
        self.assertEqual((r["category"], r["vm_action"], r["was_profile"]), ("third_party", "exclude", "standard"))
        self.assertEqual(r["vm_reasons"], ["third_party:godaddy"])

    def test_4_ip_density_alone_is_not_third_party(self):
        # Several of *our* registrable domains on one IP = owned load balancer
        a, _ = route(asset("a.example.com", shared_hosting={"detected": True, "signals": ["ip_density:3"]}))
        self.assertEqual(a["a.example.com"]["vm_action"], "include")

    def test_4_saas_cname_excluded_from_both_by_default(self):
        a, _ = route(asset("shop.example.com", cnames=["example.myshopify.com"]))
        r = a["shop.example.com"]
        self.assertEqual((r["category"], r["vm_action"], r["was_action"]), ("third_party", "exclude", "exclude"))
        self.assertEqual(r["was_reasons"], ["third_party_saas"])
        a, _ = route(asset("shop.example.com", cnames=["example.myshopify.com"]), was_include_saas=True)
        self.assertEqual(a["shop.example.com"]["was_profile"], "standard")

    def test_5_owned_shared_ip_scanned_once_all_fqdns_to_was(self):
        hosts = ["a.example.com", "b.example.com", "c.example.org"]
        a, ips = route(*[asset(h) for h in hosts])
        self.assertEqual(len(ips), 1)
        vm = ips[IP]
        self.assertEqual((vm["action"], vm["vm_category"], vm["fqdn_count"]), ("include", "owned_shared", 3))
        self.assertEqual(vm["primary_fqdn"], "a.example.com")
        for h in hosts:
            self.assertEqual(a[h]["category"], "owned_shared")
            self.assertEqual(a[h]["was_urls"], [f"https://{h}"])

    def test_5_primary_fqdn_prefers_cmdb(self):
        _, ips = route(asset("a.example.com"), asset("zz.example.com", in_cmdb=True))
        self.assertEqual(ips[IP]["primary_fqdn"], "zz.example.com")

    def test_6_paas_web_app_was_only(self):
        a, _ = route(asset("app.example.com", cloud=["app_service"]))
        r = a["app.example.com"]
        self.assertEqual((r["category"], r["vm_action"], r["was_profile"]), ("cloud_paas", "exclude", "standard"))
        self.assertEqual(r["vm_reasons"], ["cloud_paas:paas_web:app_service"])

    def test_6_storage_excluded_from_both(self):
        a, _ = route(asset("files.example.com", cloud=["s3"]))
        r = a["files.example.com"]
        self.assertEqual((r["vm_action"], r["was_action"], r["was_reasons"]), ("exclude", "exclude", ["cloud_storage"]))

    def test_6_paas_hostname_suffix(self):
        a, _ = route(asset("docs.example.com", cnames=["example.github.io"]))
        r = a["docs.example.com"]
        self.assertEqual((r["category"], r["was_reasons"]), ("cloud_paas", ["static_hosting"]))

    def test_7_non_http_only(self):
        a, ips = route(asset("vpn.example.com", ports=(22, 500), webs=[]))
        r = a["vpn.example.com"]
        self.assertEqual((r["category"], r["vm_action"], r["was_action"]), ("non_http", "include", "exclude"))
        self.assertEqual(r["was_reasons"], ["non_http_only"])
        self.assertEqual(ips[IP]["action"], "include")

    def test_8_redirect_only(self):
        a, ips = route(asset("old.example.com", ports=(80,), webs=[web("http://old.example.com", status=301)]))
        r = a["old.example.com"]
        self.assertEqual((r["category"], r["vm_action"], r["was_reasons"]),
                         ("static_or_dead", "exclude", ["redirect_only"]))
        self.assertNotIn(IP, ips)   # not an exclusion either — nothing wrong with the IP

    def test_8_followed_redirect_off_host(self):
        a, _ = route(asset("go.example.com",
                           webs=[web("https://go.example.com", final_url="https://www.example.com/landing")]))
        self.assertEqual(a["go.example.com"]["was_reasons"], ["redirect_only"])

    def test_8_same_host_redirect_targets_final_origin(self):
        a, _ = route(asset("app.example.com", ports=(80,),
                           webs=[web("http://app.example.com", final_url="https://app.example.com/login")]))
        self.assertEqual(a["app.example.com"]["was_urls"], ["https://app.example.com"])

    def test_8_parked_and_dead(self):
        a, _ = route(asset("parked.example.com", webs=[web("https://parked.example.com", title="This domain is for sale!")]),
                     asset("gone.example.com", ips=(), ports=(), webs=[]))
        self.assertEqual(a["parked.example.com"]["was_reasons"], ["parked"])
        self.assertEqual(a["parked.example.com"]["vm_action"], "exclude")
        self.assertEqual((a["gone.example.com"]["category"], a["gone.example.com"]["vm_reasons"]),
                         ("static_or_dead", ["dead"]))

    def test_8_redirect_host_with_other_services_stays_in_vm(self):
        a, _ = route(asset("mx.example.com", ports=(25, 80), webs=[web("http://mx.example.com", status=302)]))
        self.assertEqual((a["mx.example.com"]["vm_action"], a["mx.example.com"]["was_action"]), ("include", "exclude"))

    def test_8_default_page_is_vm_target_not_was(self):
        a, _ = route(asset("srv.example.com", webs=[web("https://srv.example.com", title="Welcome to nginx!")]))
        r = a["srv.example.com"]
        self.assertEqual((r["vm_action"], r["was_reasons"]), ("include", ["default_page"]))

    def test_9_json_api_routed_to_api_profile(self):
        a, _ = route(asset("api.example.com", webs=[web("https://api.example.com", ct="application/json; charset=utf-8")]))
        self.assertEqual((a["api.example.com"]["category"], a["api.example.com"]["was_profile"]), ("api", "api"))
        self.assertEqual(a["api.example.com"]["vm_action"], "include")

    def test_9_ai_endpoint_and_api_gateway(self):
        a, _ = route(asset("llm.example.com", findings=[{"source": "aimap", "tags": ["ollama"]}]),
                     asset("gw.example.com", ips=("93.184.216.20",), cloud=["api_gateway"]))
        self.assertEqual(a["llm.example.com"]["was_profile"], "api")
        self.assertEqual(a["gw.example.com"]["was_profile"], "api")

    def test_9_mixed_html_and_json_is_standard(self):
        a, _ = route(asset("m.example.com", ports=(443, 8443),
                           webs=[web("https://m.example.com"), web("https://m.example.com:8443", ct="application/json")]))
        self.assertEqual(a["m.example.com"]["was_profile"], "standard")

    def test_waf_profile_beats_api(self):
        a, _ = route(asset("api.example.com", webs=[web("https://api.example.com", ct="application/json")],
                           waf={"provider": "cloudflare", "confidence": 0.6}))
        self.assertEqual(a["api.example.com"]["was_profile"], "waf")
        self.assertIn("api", a["api.example.com"]["categories"])


class CrossCuttingRules(unittest.TestCase):

    def test_exclusion_wins_on_shared_ip(self):
        a, ips = route(asset("a.example.com"),
                       asset("b.example.com", cdn_detection={"provider": "akamai", "confidence": 0.7}))
        self.assertEqual(ips[IP]["action"], "exclude")
        self.assertEqual(a["a.example.com"]["vm_reasons"], ["cdn:akamai"])
        self.assertEqual(a["a.example.com"]["category"], "cdn")
        self.assertEqual(a["a.example.com"]["was_profile"], "standard")

    def test_owned_cidr_overrides_infra_heuristics_not_waf(self):
        cdn = asset("a.example.com", asn={"number": 13335, "org": "CLOUDFLARENET"})
        _, ips = route(cdn, owned_networks=parse_owned_networks("93.184.216.0/24"))
        self.assertEqual((ips[IP]["action"], ips[IP]["owned"]), ("include", True))
        waf = asset("w.example.com", waf={"provider": "f5", "confidence": 0.9})
        _, ips = route(waf, owned_networks=parse_owned_networks("93.184.216.0/24"))
        self.assertEqual(ips[IP]["action"], "exclude")

    def test_owned_asn(self):
        self.assertEqual(parse_owned_asns("AS64500, 64501"), {64500, 64501})
        _, ips = route(asset("a.example.com", shared_hosting={"signals": ["asn:godaddy"]}), owned_asns={64500})
        self.assertEqual(ips[IP]["action"], "include")

    def test_require_owned_sends_unknown_ips_to_review(self):
        a, ips = route(asset("a.example.com"), asset("b.example.com", ips=("93.184.217.5",)),
                       require_owned=True, owned_networks=parse_owned_networks("93.184.217.0/24"))
        self.assertEqual((ips[IP]["action"], ips[IP]["reasons"]), ("review", ["ownership_unverified"]))
        self.assertEqual(a["a.example.com"]["vm_action"], "review")
        self.assertEqual(ips["93.184.217.5"]["action"], "include")

    def test_non_routable_ip_excluded(self):
        a, ips = route(asset("int.example.com", ips=("10.1.2.3",)))
        self.assertEqual(ips["10.1.2.3"]["reasons"], ["non_routable"])
        self.assertEqual(a["int.example.com"]["category"], "static_or_dead")
        self.assertEqual(a["int.example.com"]["was_reasons"], ["non_routable"])

    def test_cmdb_only(self):
        a, ips = route(asset("shadow.example.com"), asset("known.example.com", ips=("93.184.216.20",), in_cmdb=True),
                       cmdb_only=True)
        self.assertEqual(a["shadow.example.com"]["vm_reasons"], ["not_in_cmdb"])
        self.assertEqual(a["shadow.example.com"]["was_reasons"], ["not_in_cmdb"])
        self.assertNotIn(IP, ips)
        self.assertEqual(ips["93.184.216.20"]["action"], "include")

    def test_ip_only_asset(self):
        a, ips = route(asset(IP, webs=[]), asset("a.example.com"))
        self.assertEqual(ips[IP]["fqdns"], ["a.example.com"])
        self.assertEqual(ips[IP]["vm_category"], "direct")

    def test_https_preferred_over_http_on_same_host(self):
        w = analyze_web("a.example.com", [web("http://a.example.com"), web("https://a.example.com"),
                                          web("http://a.example.com:8080", port=8080)])
        self.assertEqual(w["origins"], ["http://a.example.com:8080", "https://a.example.com"])

    def test_error_status_is_not_app_content(self):
        w = analyze_web("a.example.com", [web("https://a.example.com", status=404),
                                          web("https://a.example.com:8443", status=502, port=8443)])
        self.assertEqual((w["origins"], w["reason"]), ([], "no_app_content"))

    def test_duckdb_json_typed_fields(self):
        # read_ndjson_auto types all-null / heterogeneous fields as JSON → strings
        rec = asset("a.example.com")
        rec["network"]["waf"] = '{"provider": "f5", "confidence": 0.9}'
        rec["web"] = orjson.dumps(rec["web"]).decode()
        a, _ = route(rec)
        self.assertEqual(a["a.example.com"]["was_profile"], "waf")


def _run(*args, **kw):
    return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True, cwd=REPO, **kw)


def _jsonl(path: Path) -> list[dict]:
    return [orjson.loads(l) for l in path.read_bytes().splitlines() if l.strip()]


class _PipelineDb(unittest.TestCase):
    """Fixture: normalize.py → load_duckdb.py over a small mixed estate."""

    @classmethod
    def setUpClass(cls):
        try:
            import duckdb  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("duckdb not installed")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        w = lambda name, rows: (self.tmp / name).write_bytes(b"".join(orjson.dumps(r) + b"\n" for r in rows))
        w("dns.jsonl", [
            {"host": "app.example.com", "a": ["93.184.216.10"]},
            {"host": "api.example.com", "a": ["93.184.216.10"]},
            {"host": "cf.example.com", "a": ["104.16.1.1"]},
            {"host": "ssh.example.com", "a": ["93.184.216.30"]},
            {"host": "old.example.com", "a": ["93.184.216.40"], "cname": ["old.azurewebsites.net"]},
        ])
        w("ports.jsonl", [{"host": h, "port": p} for h, p in [
            ("app.example.com", 443), ("api.example.com", 443), ("cf.example.com", 443),
            ("ssh.example.com", 22), ("old.example.com", 443)]])
        w("httpx.jsonl", [
            {"input": "app.example.com", "url": "https://app.example.com", "port": 443, "status_code": 200,
             "content_type": "text/html", "title": "App"},
            {"input": "api.example.com", "url": "https://api.example.com", "port": 443, "status_code": 200,
             "content_type": "application/json"},
            {"input": "cf.example.com", "url": "https://cf.example.com", "port": 443, "status_code": 200,
             "content_type": "text/html", "title": "Shop"},
            {"input": "old.example.com", "url": "https://old.example.com", "port": 443, "status_code": 404},
        ])
        w("cdncheck.jsonl", [{"input": "cf.example.com", "ip": "104.16.1.1", "waf": True, "waf_name": "cloudflare"}])
        self.assets = self.tmp / "assets.jsonl"
        self.db = self.tmp / "easm.duckdb"
        self.out = self.tmp / "out"

        r = _run(SCRIPTS_DIR / "normalize.py", "--dns", self.tmp / "dns.jsonl", "--ports", self.tmp / "ports.jsonl",
                 "--http", self.tmp / "httpx.jsonl", "--cdncheck", self.tmp / "cdncheck.jsonl",
                 "--output", self.assets, "--scan-id", "s1")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = _run(SCRIPTS_DIR / "load_duckdb.py", "--input", self.assets, "--db", self.db, "--no-parquet")
        self.assertEqual(r.returncode, 0, r.stderr)

    def tearDown(self):
        self._tmp.cleanup()

    def _query(self, sql):
        import duckdb
        con = duckdb.connect(str(self.db), read_only=True)
        try:
            return con.execute(sql).fetchall()
        finally:
            con.close()



class EndToEnd(_PipelineDb):
    """normalize.py → load_duckdb.py → cmdb_scope_export.py --db."""

    def test_db_mode_files_tables_and_views(self):
        r = _run(SCRIPTS_DIR / "cmdb_scope_export.py", "--db", self.db, "--output-dir", self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Tenable Scope Routing", r.stderr)

        read = lambda n: (self.out / n).read_text().split()
        self.assertEqual(read("tenable_vm_include.txt"), ["93.184.216.10", "93.184.216.30", "93.184.216.40"])
        self.assertEqual(read("tenable_vm_exclude.txt"), ["104.16.1.1"])
        self.assertEqual(read("tenable_vm_review.txt"), [])
        self.assertEqual(read("tenable_was_targets.txt"), ["https://app.example.com"])
        self.assertEqual(read("tenable_was_waf_targets.txt"), ["https://cf.example.com"])
        self.assertEqual(read("tenable_was_api_targets.txt"), ["https://api.example.com"])

        rows = {r["fqdn"]: r for r in _jsonl(self.out / "tenable_scope.jsonl")}
        self.assertEqual(rows["old.example.com"]["category"], "direct")
        self.assertEqual(rows["ssh.example.com"]["category"], "non_http")

        self.assertEqual(self._query("SELECT target_ip, vm_category, fqdn_count FROM v_tenable_vm_scope"),
                         [("93.184.216.10", "owned_shared", 2), ("93.184.216.30", "direct", 1),
                          ("93.184.216.40", "direct", 1)])
        excl = dict(self._query("SELECT target_ip, reasons FROM v_tenable_vm_exclusions"))
        self.assertTrue(any(x.startswith(("cdn:", "waf:")) for x in excl["104.16.1.1"]))
        self.assertEqual(self._query("SELECT target_url, waf_provider FROM v_tenable_was_scope_waf"),
                         [("https://cf.example.com", "cloudflare")])
        self.assertEqual(self._query("SELECT target_url FROM v_tenable_was_scope_api"), [("https://api.example.com",)])
        self.assertEqual(self._query("SELECT SUM(assets) FROM v_tenable_scope_summary"), [(5,)])

        if _has_xlsxwriter():
            import zipfile
            with zipfile.ZipFile(self.out / "tenable_scope.xlsx") as z:
                names = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode())
            self.assertEqual(names, ["Summary", "All", "Tenable VM Candidates", "Tenable WAS Candidates", "Columns"])

    def test_reload_drops_stale_routing(self):
        r = _run(SCRIPTS_DIR / "cmdb_scope_export.py", "--db", self.db, "--output-dir", self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = _run(SCRIPTS_DIR / "load_duckdb.py", "--input", self.assets, "--db", self.db, "--no-parquet")
        self.assertEqual(r.returncode, 0, r.stderr)
        left = self._query("""SELECT table_name FROM information_schema.tables
                              WHERE table_name LIKE '%tenable%'""")
        self.assertEqual(left, [])

    def test_empty_scope_still_creates_tables(self):
        r = _run(SCRIPTS_DIR / "cmdb_scope_export.py", "--db", self.db, "--output-dir", self.out, "--cmdb-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._query("SELECT COUNT(*) FROM v_tenable_vm_scope"), [(0,)])
        self.assertEqual((self.out / "tenable_was_targets.txt").read_text(), "")

    def test_assets_mode(self):
        r = _run(SCRIPTS_DIR / "cmdb_scope_export.py", "--assets", self.assets, "--output-dir", self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("93.184.216.40", (self.out / "tenable_vm_include.txt").read_text())
        self.assertEqual((self.out / "tenable_vm_exclude.txt").read_text().split(), ["104.16.1.1"])


class DashboardApi(_PipelineDb):
    """dashboard/app.py /api/tenable-scope endpoints over a routed database."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            import fastapi  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("fastapi not installed")
        sys.path.insert(0, str(REPO))
        from dashboard import app as dash
        cls.dash = dash

    def setUp(self):
        super().setUp()
        r = _run(SCRIPTS_DIR / "cmdb_scope_export.py", "--db", self.db, "--output-dir", self.out,
                 "--owned-cidrs", "93.184.216.0/24")
        self.assertEqual(r.returncode, 0, r.stderr)
        import duckdb
        self.con = duckdb.connect(str(self.db), read_only=True)

    def tearDown(self):
        self.con.close()
        super().tearDown()

    def _list(self, kind, **kw):
        args = dict(q="", category="", vm="", was="", cmdb="", page=1, per_page=50)
        args.update(kw)
        return self.dash.tenable_scope_list(db=self.con, kind=kind, **args)

    def test_overview(self):
        d = self.dash.tenable_scope(db=self.con)
        meta = d["meta"]
        self.assertEqual((meta["require_owned"], meta["cmdb_only"]), (False, False))
        self.assertEqual(meta["owned_cidrs"], ["93.184.216.0/24"])
        self.assertEqual((d["vm"]["include"]["ips"], d["vm"]["include"]["fqdns"]), (3, 4))
        self.assertEqual(d["was_urls"], {"standard": 1, "waf": 1, "api": 1})
        self.assertEqual(d["assets"]["total"], 5)
        kinds = {r["kind"] for r in d["vm_reasons"]}
        self.assertIn("cdn", kinds)
        self.assertEqual(sum(c["assets"] for c in d["categories"]), 5)

    def test_lists_and_filters(self):
        vm = self._list("vm_include")
        self.assertEqual([r["target_ip"] for r in vm["items"]], ["93.184.216.10", "93.184.216.30", "93.184.216.40"])
        self.assertEqual(self._list("vm_include", q="ssh")["total"], 1)
        self.assertEqual([r["target_url"] for r in self._list("was_waf")["items"]], ["https://cf.example.com"])
        self.assertEqual(self._list("assets", category="direct")["items"][0]["fqdn"], "old.example.com")
        self.assertEqual(self._list("assets", was="exclude")["total"], 2)
        self.assertEqual(self._list("assets", cmdb="1")["total"], 0)
        page = self._list("assets", per_page=2, page=3)
        self.assertEqual((page["pages"], len(page["items"])), (3, 1))
        with self.assertRaises(self.dash.HTTPException):
            self._list("bogus")

    def test_exports(self):
        r = self.dash.tenable_scope_export(db=self.con, kind="vm_exclude")
        self.assertEqual(r.body.decode().split(), ["104.16.1.1"])
        self.assertIn('filename="tenable_vm_exclude.txt"', r.headers["content-disposition"])
        csv = self.dash.tenable_scope_export(db=self.con, kind="assets").body.decode()
        self.assertTrue(csv.startswith("scan_id,fqdn,"))
        self.assertIn("cdn:cloudflare", csv)

    @unittest.skipUnless(_has_xlsxwriter(), "XlsxWriter not installed")
    def test_xlsx_export(self):
        r = self.dash.tenable_scope_export(db=self.con, kind="xlsx")
        self.assertEqual(r.media_type, self.dash._XLSX_MEDIA_TYPE)
        self.assertIn('filename="tenable_scope_s1.xlsx"', r.headers["content-disposition"])
        self.assertTrue(r.body.startswith(b"PK"))

        from tenable_xlsx import tenable_workbook_data
        data = tenable_workbook_data(self.con)
        n_vm = self._query("SELECT COUNT(*) FROM tenable_vm_targets WHERE action IN ('include', 'review')")[0][0]
        n_was = self._query("""SELECT COUNT(DISTINCT u) FROM (SELECT UNNEST(was_urls) AS u FROM tenable_scope
                                WHERE was_action = 'include')""")[0][0]
        self.assertEqual((len(data["vm"]), len(data["was"]), len(data["assets"])), (n_vm, n_was, 5))
        self.assertEqual([r["was_profile"] for r in data["was"]], ["standard", "waf", "api"])
        waf = next(r for r in data["was"] if r["was_profile"] == "waf")
        self.assertEqual((waf["target_url"], waf["url_status"], waf["url_title"]), ("https://cf.example.com", 200, "Shop"))
        self.assertIn("allow-list", waf["policy"])
        shared = next(r for r in data["vm"] if r["target_ip"] == "93.184.216.10")
        self.assertEqual((shared["vm_category"], shared["owned"]), ("owned_shared", True))
        app = next(a for a in data["assets"] if a["fqdn"] == "app.example.com")
        self.assertEqual((app["http_status"], app["title"]), ([200], "App"))

    def _query(self, sql):
        return self.con.execute(sql).fetchall()

    def test_missing_routing_is_404(self):
        self.con.close()
        r = _run(SCRIPTS_DIR / "load_duckdb.py", "--input", self.assets, "--db", self.db, "--no-parquet")
        self.assertEqual(r.returncode, 0, r.stderr)
        import duckdb
        self.con = duckdb.connect(str(self.db), read_only=True)
        with self.assertRaises(self.dash.HTTPException) as ctx:
            self.dash.tenable_scope(db=self.con)
        self.assertEqual(ctx.exception.status_code, 404)


class LivecheckModeUnchanged(unittest.TestCase):
    def test_report_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "lc.jsonl").write_bytes(b"".join(orjson.dumps(r) + b"\n" for r in [
                {"fqdn": "a.example.com", "in_cmdb": True, "scope_action": "keep", "a_records": ["93.184.216.1"]},
                {"fqdn": "b.example.com", "in_cmdb": True, "scope_action": "exclude_cdn", "cdn_provider": "akamai"},
                {"fqdn": "c.example.com", "in_cmdb": False, "scope_action": "keep"},
            ]))
            r = _run(SCRIPTS_DIR / "cmdb_scope_export.py", "--report", tmp / "lc.jsonl", "--output-dir", tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((tmp / "tenable_include.txt").read_text().split(), ["93.184.216.1", "a.example.com"])
            self.assertEqual((tmp / "tenable_exclude.txt").read_text(), "b.example.com  # cdn_akamai\n")


class RunShStage(unittest.TestCase):
    def _stages(self, *args):
        r = subprocess.run(["bash", str(REPO / "run.sh"), "--dry-run", *args], capture_output=True,
                           text=True, cwd=REPO, env=os.environ.copy())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return [l.split(": ")[1].strip() for l in (r.stdout + r.stderr).splitlines() if "Would run:" in l]

    def test_scope_runs_after_load(self):
        stages = self._stages()
        self.assertEqual(stages[-2:], ["load", "scope"])

    def test_scope_resumable(self):
        self.assertEqual(self._stages("--from", "scope"), ["scope"])

    def test_livecheck_mode_has_no_scope_stage(self):
        self.assertNotIn("scope", self._stages("--mode", "livecheck"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
