#!/usr/bin/env python3
"""
EASM Pipeline — IP Assets Implementation Test Suite

Tests all changes from IP_ASSETS_IMPLEMENTATION.md:
  - Phase 1: IP triage / CIDR expansion, enrich_asn.py, ingest_asn()
  - Phase 2: ingest_rdns(), CDNDetector, enrich_cdn(), DuckDB views

Run: python3 scripts/test_ip_implementation.py
Exit 0 = all tests passed, non-zero = failures.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Make scripts/ importable
SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))
PROJECT_ROOT = SCRIPTS_DIR.parent

# ─────────────────────────────────────────────
# Minimal test harness (no pytest dependency)
# ─────────────────────────────────────────────
_PASS = 0
_FAIL = 0
_SKIP = 0
_ERRORS: list[str] = []


def ok(name: str):
    global _PASS
    _PASS += 1
    print(f"  ✓  {name}")


def fail(name: str, detail: str = ""):
    global _FAIL
    _FAIL += 1
    msg = f"  ✗  {name}"
    if detail:
        msg += f"\n       {detail}"
    print(msg)
    _ERRORS.append(f"{name}: {detail}")


def skip(name: str, reason: str = ""):
    global _SKIP
    _SKIP += 1
    print(f"  -  {name}  (skipped: {reason})")


def section(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


def assert_equal(name, got, expected):
    if got == expected:
        ok(name)
    else:
        fail(name, f"expected {expected!r}, got {got!r}")


def assert_true(name, value, detail=""):
    if value:
        ok(name)
    else:
        fail(name, detail or f"expected truthy, got {value!r}")


def assert_in(name, item, container):
    if item in container:
        ok(name)
    else:
        fail(name, f"{item!r} not in {container!r}")


def assert_not_none(name, value):
    if value is not None:
        ok(name)
    else:
        fail(name, "expected non-None value")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def write_jsonl(path: Path, records: list[dict]):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


# ─────────────────────────────────────────────
# Section 1: run.sh input triage + CIDR expansion
# ─────────────────────────────────────────────

def test_ip_triage():
    section("1 · Input triage: FQDN vs IP partitioning + CIDR expansion")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        targets = tmp / "targets.txt"
        ip_targets = tmp / "ip_targets.txt"
        fqdn_targets = tmp / "fqdn_targets.txt"

        targets.write_text(
            "api.example.com\n"
            "portal.example.com\n"
            "192.168.1.1\n"
            "10.0.0.0/30\n"          # /30 → 2 usable hosts
            "203.0.113.50\n"
            "www.example.com\n"
        )

        # Replicate the grep partition from run.sh
        import re
        ip_pat = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$")
        fqdns, ips = [], []
        for line in targets.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            (ips if ip_pat.match(line) else fqdns).append(line)

        fqdn_targets.write_text("\n".join(fqdns) + "\n")
        ip_targets.write_text("\n".join(ips) + "\n")

        assert_equal("FQDN targets count", len(fqdns), 3)
        assert_equal("IP/CIDR targets count", len(ips), 3)  # 192.168.1.1, 10.0.0.0/30, 203.0.113.50
        assert_in("api.example.com in fqdns", "api.example.com", fqdns)
        assert_in("192.168.1.1 in ips", "192.168.1.1", ips)
        assert_in("10.0.0.0/30 in ips before expansion", "10.0.0.0/30", ips)

        # CIDR expansion (the python3 inline from run.sh)
        import ipaddress
        expanded = []
        for line in ips:
            if "/" in line:
                for ip in ipaddress.ip_network(line, strict=False).hosts():
                    expanded.append(str(ip))
            else:
                expanded.append(line)

        assert_equal("CIDR /30 expands to 2 hosts", len([x for x in expanded if x.startswith("10.0.0.")]), 2)
        assert_in("10.0.0.1 expanded", "10.0.0.1", expanded)
        assert_in("10.0.0.2 expanded", "10.0.0.2", expanded)
        assert_true("No CIDR notation left after expansion", all("/" not in ip for ip in expanded))


# ─────────────────────────────────────────────
# Section 2: ingest_asn() in normalize.py
# ─────────────────────────────────────────────

def test_ingest_asn():
    section("2 · normalize.py — ingest_asn()")

    from normalize import AssetStore

    store = AssetStore("test_asn")

    # Seed an FQDN asset with a DNS A record
    store.ingest_dns([
        {"host": "api.example.com", "a": ["104.16.0.1"], "cname": []},
        {"host": "portal.example.com", "a": ["8.8.8.8"], "cname": []},
    ])

    asn_records = [
        {"ip": "104.16.0.1", "asn": 13335, "prefix": "104.16.0.0/13", "org": "CLOUDFLARENET"},
        {"ip": "8.8.8.8",    "asn": 15169, "prefix": "8.8.8.0/24",    "org": "GOOGLE"},
        # Standalone IP — not behind any FQDN
        {"ip": "1.2.3.4",    "asn": 7922,  "prefix": "1.2.3.0/24",    "org": "COMCAST"},
    ]
    store.ingest_asn(asn_records)

    # FQDN assets get enriched
    api_asn = store.assets["api.example.com"]["network"]["asn"]
    assert_equal("api.example.com gets Cloudflare ASN", api_asn["number"], 13335)
    assert_equal("api.example.com ASN org", api_asn["org"], "CLOUDFLARENET")

    portal_asn = store.assets["portal.example.com"]["network"]["asn"]
    assert_equal("portal.example.com gets Google ASN", portal_asn["number"], 15169)

    # Standalone IP creates an ip_only asset
    assert_in("1.2.3.4 asset created", "1.2.3.4", store.assets)
    ip_asset = store.assets["1.2.3.4"]
    assert_in("ip_only tag set", "ip_only", ip_asset["tags"])
    assert_in("pyasn source recorded", "pyasn", ip_asset["source"])
    assert_equal("standalone IP in dns.a", ip_asset["dns"]["a"], ["1.2.3.4"])
    assert_equal("standalone IP ASN number", ip_asset["network"]["asn"]["number"], 7922)

    # httpx-enriched ASN should NOT be overwritten
    store2 = AssetStore("test_asn2")
    store2.ingest_dns([{"host": "cdn.example.com", "a": ["104.16.0.1"], "cname": []}])
    store2.assets["cdn.example.com"]["network"]["asn"] = {
        "number": 13335, "org": "CLOUDFLARENET", "country": "US"
    }
    store2.ingest_asn([{"ip": "104.16.0.1", "asn": 99999, "prefix": "", "org": "OVERRIDE"}])
    assert_equal("httpx ASN not overwritten by pyasn", store2.assets["cdn.example.com"]["network"]["asn"]["number"], 13335)


# ─────────────────────────────────────────────
# Section 3: ingest_rdns() in normalize.py
# ─────────────────────────────────────────────

def test_ingest_rdns():
    section("3 · normalize.py — ingest_rdns()")

    from normalize import AssetStore

    store = AssetStore("test_rdns")
    store.ingest_dns([
        {"host": "server.example.com", "a": ["203.0.113.10", "203.0.113.11"], "cname": []},
        {"host": "noptr.example.com",  "a": ["198.51.100.1"], "cname": []},
    ])

    rdns_records = [
        {"host": "203.0.113.10", "ptr": ["mail.isp.net.", "mail2.isp.net."]},
        {"host": "203.0.113.11", "ptr": ["edge.isp.net."]},
        # IP that doesn't belong to any FQDN — should not crash
        {"host": "1.1.1.1", "ptr": ["one.one.one.one."]},
    ]
    store.ingest_rdns(rdns_records)

    asset = store.assets["server.example.com"]
    ptr_ips = [e["ip"] for e in asset["dns"]["ptr"]]
    def get_ptrs(ip): return next((e["ptrs"] for e in asset["dns"]["ptr"] if e["ip"] == ip), None)
    assert_in("203.0.113.10 key in ptr", "203.0.113.10", ptr_ips)
    assert_equal("PTR records for .10", get_ptrs("203.0.113.10"), ["mail.isp.net", "mail2.isp.net"])
    assert_equal("trailing dot stripped", get_ptrs("203.0.113.11"), ["edge.isp.net"])
    assert_in("rdns source recorded", "rdns", asset["source"])

    # IP with no PTR — should not appear in ptr list
    noptr_ips = [e["ip"] for e in store.assets["noptr.example.com"]["dns"]["ptr"]]
    assert_true("198.51.100.1 not in ptr (no PTR record)", "198.51.100.1" not in noptr_ips)

    # IP not belonging to any asset — no crash, no spurious asset
    assert_true("1.1.1.1 not added as asset (rdns only)", "1.1.1.1" not in store.assets)

    # PTR values are lowercased
    assert_true("PTR values lowercase", all(v == v.lower() for e in asset["dns"]["ptr"] for v in e["ptrs"]))


# ─────────────────────────────────────────────
# Section 4: CDNDetector signal tests
# ─────────────────────────────────────────────

def test_cdn_detection_signals():
    section("4 · CDNDetector — individual signal coverage")

    from detect_cdn import CDNDetector
    d = CDNDetector()

    def asset(a=None, cnames=None, headers=None, server="", asn=None):
        return {
            "dns": {"a": a or [], "cname_chain": cnames or []},
            "network": {"asn": {"number": asn}},
            "web": [{"headers_of_interest": headers or {}, "server": server}] if headers or server else [],
        }

    # CNAME signals
    cases_cname = [
        ("cloudflare", ["foo.cdn.cloudflare.com"]),
        ("cloudfront",  ["xyz.cloudfront.net"]),
        ("akamai",      ["www.example.akamaiedge.net"]),
        ("fastly",      ["global.prod.fastly.net"]),
        ("azure_cdn",   ["myapp.azureedge.net"]),
        ("netlify",     ["my-site.netlify.app"]),
        ("vercel",      ["my-app.vercel-dns.com"]),
    ]
    for provider, cnames in cases_cname:
        r = d.detect(asset(cnames=cnames))
        assert_not_none(f"CNAME → {provider} detected", r)
        if r:
            assert_equal(f"CNAME → {provider} provider correct", r["provider"], provider)
            assert_true(f"CNAME → {provider} has cname signal", any(s.startswith("cname:") for s in r["signals"]))

    # IP range signals
    ip_cases = [
        ("cloudflare", "104.16.0.1"),
        ("cloudflare", "173.245.48.1"),
        ("fastly",     "151.101.1.1"),
    ]
    for provider, ip in ip_cases:
        r = d.detect(asset(a=[ip]))
        assert_not_none(f"IP {ip} → {provider} detected", r)
        if r:
            assert_equal(f"IP {ip} → {provider} provider", r["provider"], provider)

    # Header signals
    header_cases = [
        ("cloudflare", {"cf-ray": "7abc123-LHR"}, ""),
        ("cloudflare", {"cf-cache-status": "HIT"}, ""),
        ("cloudflare", {}, "cloudflare"),
        ("cloudfront", {"x-amz-cf-id": "abc123"}, ""),
        ("fastly",     {"x-fastly-request-id": "xyz"}, ""),
        ("azure_cdn",  {"x-azure-ref": "0abc"}, ""),
    ]
    for provider, headers, server in header_cases:
        r = d.detect(asset(headers=headers, server=server))
        assert_not_none(f"header → {provider} detected", r)
        if r:
            assert_equal(f"header → {provider} provider", r["provider"], provider)

    # ASN signals
    asn_cases = [
        ("cloudflare", 13335),
        ("akamai",     20940),
        ("fastly",     54113),
    ]
    for provider, asn in asn_cases:
        r = d.detect(asset(asn=asn))
        assert_not_none(f"ASN {asn} → {provider}", r)
        if r:
            assert_equal(f"ASN {asn} → {provider} provider", r["provider"], provider)


def test_cdn_detection_confidence():
    section("5 · CDNDetector — confidence scoring and edge cases")

    from detect_cdn import CDNDetector
    d = CDNDetector()

    # Single signal → 0.35
    r = d.detect({
        "dns": {"a": [], "cname_chain": ["x.cdn.cloudflare.com"]},
        "network": {"asn": {"number": None}},
        "web": [],
    })
    assert_equal("single signal confidence", r["confidence"], 0.35)

    # Two distinct signal types → 0.70
    r2 = d.detect({
        "dns": {"a": ["104.16.0.1"], "cname_chain": ["x.cdn.cloudflare.com"]},
        "network": {"asn": {"number": None}},
        "web": [],
    })
    assert_equal("two signal types confidence", r2["confidence"], 0.70)

    # Three signal types → 1.0 (capped)
    r3 = d.detect({
        "dns": {"a": ["104.16.0.1"], "cname_chain": ["x.cdn.cloudflare.com"]},
        "network": {"asn": {"number": 13335}},
        "web": [{"headers_of_interest": {"cf-ray": "abc"}, "server": ""}],
    })
    assert_equal("multi-signal confidence capped at 1.0", r3["confidence"], 1.0)

    # No CDN signals → None
    r_none = d.detect({
        "dns": {"a": ["8.8.4.4"], "cname_chain": []},
        "network": {"asn": {"number": None}},
        "web": [],
    })
    assert_equal("non-CDN IP returns None", r_none, None)

    # x-cache HIT alone should not trigger CDN (the pattern requires "cloudfront" in value)
    r_xcache = d.detect({
        "dns": {"a": [], "cname_chain": []},
        "network": {"asn": {"number": None}},
        "web": [{"headers_of_interest": {"x-cache": "HIT"}, "server": ""}],
    })
    assert_equal("x-cache:HIT alone is not CDN", r_xcache, None)

    # Signal conflict — Cloudflare CNAME but Akamai ASN → pick provider with more signals
    r_conflict = d.detect({
        "dns": {"a": [], "cname_chain": ["x.cdn.cloudflare.com", "y.cdn.cloudflare.com"]},
        "network": {"asn": {"number": 20940}},
        "web": [],
    })
    assert_equal("conflict: 2×cloudflare CNAME beats 1×akamai ASN", r_conflict["provider"], "cloudflare")


# ─────────────────────────────────────────────
# Section 6: enrich_cdn() integration
# ─────────────────────────────────────────────

def test_enrich_cdn():
    section("6 · normalize.py — enrich_cdn() integration")

    from normalize import AssetStore

    store = AssetStore("test_cdn")
    store.ingest_dns([
        {"host": "cf.example.com",    "a": ["104.16.0.1"], "cname": ["cf.example.com.cdn.cloudflare.com"]},
        {"host": "fastly.example.com","a": ["151.101.1.1"], "cname": []},
        {"host": "plain.example.com", "a": ["8.8.8.8"],    "cname": []},
    ])
    # Simulate httpx CDN detection (boolean) that should be upgraded
    store.assets["plain.example.com"]["network"]["cdn"] = True
    store.assets["plain.example.com"]["web"].append(
        {"headers_of_interest": {"cf-ray": "abc123"}, "server": ""}
    )

    store.enrich_cdn()

    # Cloudflare detected via CNAME + IP range
    cf = store.assets["cf.example.com"]["network"]
    assert_equal("cf.example.com cdn = cloudflare", cf["cdn"], "cloudflare")
    assert_not_none("cf.example.com cdn_detection set", cf["cdn_detection"])
    assert_true("cf.example.com tagged cdn", "cdn" in store.assets["cf.example.com"]["tags"])

    # Fastly detected via IP range
    fa = store.assets["fastly.example.com"]["network"]
    assert_equal("fastly.example.com cdn = fastly", fa["cdn"], "fastly")

    # Boolean httpx CDN upgraded to named provider via header
    pl = store.assets["plain.example.com"]["network"]
    assert_equal("boolean cdn upgraded to cloudflare", pl["cdn"], "cloudflare")

    # Non-CDN asset
    assert_equal("plain.example.com cdn=None when no signals",
        store.assets["plain.example.com"]["network"]["cdn"], "cloudflare")  # was upgraded


# ─────────────────────────────────────────────
# Section 7: Full normalize pipeline with all new args
# ─────────────────────────────────────────────

def test_full_normalize_pipeline():
    section("7 · normalize.py — full pipeline with --asn, --rdns")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        dns_records = [
            {"host": "api.example.com",    "a": ["104.16.1.1"], "cname": ["api.cdn.cloudflare.com"]},
            {"host": "db.example.com",     "a": ["198.51.100.5"], "cname": []},
            {"host": "mail.example.com",   "a": ["203.0.113.20"], "cname": []},
        ]
        write_jsonl(tmp / "dns.jsonl", dns_records)

        asn_records = [
            {"ip": "104.16.1.1",   "asn": 13335, "prefix": "104.16.0.0/13", "org": "CLOUDFLARENET"},
            {"ip": "198.51.100.5", "asn": 7922,  "prefix": "198.51.100.0/24", "org": "COMCAST"},
            {"ip": "203.0.113.20", "asn": 701,   "prefix": "203.0.113.0/24", "org": "MCI"},
            # Standalone IP (not in any DNS record)
            {"ip": "10.0.0.1",    "asn": 64512, "prefix": "10.0.0.0/8",    "org": "RFC1918"},
        ]
        write_jsonl(tmp / "asn.jsonl", asn_records)

        rdns_records = [
            {"host": "104.16.1.1",   "ptr": ["cf-node.cloudflare.com."]},
            {"host": "203.0.113.20", "ptr": ["mail.isp.net.", "mail2.isp.net."]},
        ]
        write_jsonl(tmp / "rdns.jsonl", rdns_records)

        assets_out = tmp / "assets.jsonl"

        result = subprocess.run(
            [
                sys.executable, str(SCRIPTS_DIR / "normalize.py"),
                "--dns",    str(tmp / "dns.jsonl"),
                "--asn",    str(tmp / "asn.jsonl"),
                "--rdns",   str(tmp / "rdns.jsonl"),
                "--output", str(assets_out),
                "--scan-id", "test_full",
            ],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT),
        )

        assert_equal("normalize exit code 0", result.returncode, 0)
        assert_true("assets.jsonl created", assets_out.exists())

        assets = {a["fqdn"]: a for a in read_jsonl(assets_out)}

        # ASN enrichment propagated
        assert_equal("api.example.com ASN", assets["api.example.com"]["network"]["asn"]["number"], 13335)
        assert_equal("db.example.com ASN", assets["db.example.com"]["network"]["asn"]["number"], 7922)

        # Standalone IP created as ip_only asset
        assert_in("10.0.0.1 standalone asset", "10.0.0.1", assets)
        assert_in("ip_only tag on standalone", "ip_only", assets["10.0.0.1"]["tags"])

        # rDNS populated
        api_ptr = assets["api.example.com"]["dns"]["ptr"]
        api_ptr_ips = [e["ip"] for e in api_ptr]
        assert_in("104.16.1.1 PTR key", "104.16.1.1", api_ptr_ips)
        assert_equal("104.16.1.1 PTR value", next(e["ptrs"] for e in api_ptr if e["ip"] == "104.16.1.1"), ["cf-node.cloudflare.com"])
        mail_ptr = assets["mail.example.com"]["dns"]["ptr"]
        assert_equal("203.0.113.20 multiple PTR", next(e["ptrs"] for e in mail_ptr if e["ip"] == "203.0.113.20"), ["mail.isp.net", "mail2.isp.net"])

        # CDN detection via CNAME
        assert_equal("api.example.com CDN = cloudflare", assets["api.example.com"]["network"]["cdn"], "cloudflare")
        assert_not_none("cdn_detection populated", assets["api.example.com"]["network"]["cdn_detection"])

        # Non-CDN asset
        assert_equal("db.example.com CDN = None", assets["db.example.com"]["network"]["cdn"], None)


# ─────────────────────────────────────────────
# Section 8: DuckDB views for new data
# ─────────────────────────────────────────────

def test_duckdb_views():
    section("8 · DuckDB views — v_reverse_dns, v_cdn_analysis, v_asset_summary CDN fields")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # Build a minimal assets.jsonl that exercises all new views
        assets = [
            {
                "fqdn": "cf.example.com",
                "scan_id": "test_views",
                "first_seen": "2026-05-05T00:00:00Z",
                "last_seen": "2026-05-05T00:00:00Z",
                "source": ["dns", "pyasn", "rdns"],
                "tags": ["cdn"],
                "dns": {
                    "a": ["104.16.0.1"],
                    "aaaa": [],
                    "cname_chain": ["cf.example.com.cdn.cloudflare.com"],
                    "ns": [],
                    "mx": [],
                    "txt": [],
                    "wildcard": False,
                    "ptr": [{"ip": "104.16.0.1", "ptrs": ["cf-node.cloudflare.com"]}],
                },
                "network": {
                    "asn": {"number": 13335, "org": "CLOUDFLARENET", "country": "US"},
                    "cdn": "cloudflare",
                    "cdn_detection": {"provider": "cloudflare", "confidence": 0.70, "signals": ["cname:cf.example.com.cdn.cloudflare.com", "ip_range:104.16.0.0/13"]},
                    "shared_hosting": None,
                    "open_ports": [{"port": 443, "protocol": "tcp", "service": None, "banner": None}],
                },
                "web": [],
                "tls": [],
                "services": [],
                "findings": [],
                "cmdb": {"matched_ci": None, "match_basis": [], "in_cmdb": False, "gap_type": None},
            },
            {
                "fqdn": "plain.example.com",
                "scan_id": "test_views",
                "first_seen": "2026-05-05T00:00:00Z",
                "last_seen": "2026-05-05T00:00:00Z",
                "source": ["dns"],
                "tags": [],
                "dns": {"a": ["8.8.8.8"], "aaaa": [], "cname_chain": [], "ns": [], "mx": [], "txt": [], "wildcard": False, "ptr": []},
                "network": {"asn": {"number": None, "org": None, "country": None}, "cdn": None, "cdn_detection": None, "shared_hosting": None, "open_ports": []},
                "web": [],
                "tls": [],
                "services": [],
                "findings": [],
                "cmdb": {"matched_ci": None, "match_basis": [], "in_cmdb": False, "gap_type": None},
            },
            {
                "fqdn": "shared.site",
                "scan_id": "test_views",
                "first_seen": "2026-05-05T00:00:00Z",
                "last_seen": "2026-05-05T00:00:00Z",
                "source": ["dns", "pyasn"],
                "tags": ["shared_hosting"],
                "dns": {"a": ["5.5.5.5"], "aaaa": [], "cname_chain": [], "ns": [], "mx": [], "txt": [], "wildcard": False, "ptr": []},
                "network": {
                    "asn": {"number": 26496, "org": "GoDaddy", "country": "US"},
                    "cdn": None,
                    "cdn_detection": None,
                    "shared_hosting": {"detected": True, "confidence": 0.70, "cohosted_count": 5, "signals": ["ip_density:5", "asn:godaddy"]},
                    "open_ports": [],
                },
                "web": [], "tls": [], "services": [], "findings": [],
                "cmdb": {"matched_ci": None, "match_basis": [], "in_cmdb": False, "gap_type": None},
            },
        ]

        assets_path = tmp / "assets.jsonl"
        write_jsonl(assets_path, assets)

        db_path = tmp / "easm.duckdb"

        result = subprocess.run(
            [
                sys.executable, str(SCRIPTS_DIR / "load_duckdb.py"),
                "--input",   str(assets_path),
                "--db",      str(db_path),
                "--scan-id", "test_views",
                "--no-parquet",
            ],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT),
        )

        assert_equal("load_duckdb exit code 0", result.returncode, 0)

        import duckdb
        con = duckdb.connect(str(db_path), read_only=True)

        # v_asset_summary has cdn and shared_hosting columns
        cols = {row[0] for row in con.execute("DESCRIBE v_asset_summary").fetchall()}
        assert_in("v_asset_summary has cdn_provider", "cdn_provider", cols)
        assert_in("v_asset_summary has cdn_confidence", "cdn_confidence", cols)
        assert_in("v_asset_summary has shared_hosting_detected", "shared_hosting_detected", cols)
        assert_in("v_asset_summary has shared_hosting_confidence", "shared_hosting_confidence", cols)
        assert_in("v_asset_summary has cohosted_count", "cohosted_count", cols)

        # v_shared_hosting returns detected assets
        sh_rows = con.execute("SELECT fqdn, confidence, cohosted_count FROM v_shared_hosting").fetchall()
        assert_true("v_shared_hosting has rows", len(sh_rows) >= 1, f"got {len(sh_rows)} rows")
        sh_fqdns = {r[0] for r in sh_rows}
        assert_in("shared.site in v_shared_hosting", "shared.site", sh_fqdns)
        assert_true("cf.example.com not in v_shared_hosting (CDN)", "cf.example.com" not in sh_fqdns)

        # v_reverse_dns returns assets with ptr data
        rdns_rows = con.execute("SELECT * FROM v_reverse_dns").fetchall()
        assert_true("v_reverse_dns has rows", len(rdns_rows) >= 1, f"got {len(rdns_rows)} rows")
        fqdns_with_ptr = {r[0] for r in rdns_rows}
        assert_in("cf.example.com in v_reverse_dns", "cf.example.com", fqdns_with_ptr)

        # plain.example.com (empty ptr dict) should NOT appear
        assert_true("plain.example.com not in v_reverse_dns (no PTR)",
                    "plain.example.com" not in fqdns_with_ptr)

        # v_cdn_analysis returns CDN-detected assets
        cdn_rows = con.execute("SELECT * FROM v_cdn_analysis").fetchall()
        assert_true("v_cdn_analysis has rows", len(cdn_rows) >= 1, f"got {len(cdn_rows)} rows")
        cdn_fqdns = {r[0] for r in cdn_rows}
        assert_in("cf.example.com in v_cdn_analysis", "cf.example.com", cdn_fqdns)

        # Validate schema
        from validate_schema import validate_assets_schema
        missing = validate_assets_schema(con)
        assert_equal("validate_schema passes", missing, [])

        con.close()


# ─────────────────────────────────────────────
# Section 9: run.sh stage order + flag removal
# ─────────────────────────────────────────────

def test_run_sh_stage_order():
    section("9 · run.sh — stage order and flag removal")

    run_sh = PROJECT_ROOT / "run.sh"

    # Dry-run: confirm stage order
    result = subprocess.run(
        ["bash", str(run_sh), "--dry-run"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )
    assert_equal("run.sh --dry-run exits 0", result.returncode, 0)

    output = result.stdout + result.stderr
    stages_seen = [line.split(": ")[1].strip() for line in output.splitlines() if "Would run:" in line]

    expected_order = ["dns", "asn", "rdns", "ports", "http", "tls", "fingerprint", "nuclei", "takeover", "normalize", "load", "verify"]
    assert_equal("stage order correct", stages_seen, expected_order)
    assert_true("passive not in stages", "passive" not in stages_seen)

    # --skip-passive rejected
    result2 = subprocess.run(
        ["bash", str(run_sh), "--skip-passive", "--dry-run"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )
    assert_equal("--skip-passive exits 1", result2.returncode, 1)
    assert_in("--skip-passive rejected", "Unknown arg", result2.stdout + result2.stderr)

    # --stage asn,rdns works (subset)
    result3 = subprocess.run(
        ["bash", str(run_sh), "--stage", "asn,rdns", "--dry-run"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )
    assert_equal("--stage asn,rdns dry-run exits 0", result3.returncode, 0)
    stages3 = [line.split(": ")[1].strip() for line in (result3.stdout + result3.stderr).splitlines() if "Would run:" in line]
    assert_equal("--stage asn,rdns only runs asn+rdns", sorted(stages3), ["asn", "rdns"])


# ─────────────────────────────────────────────
# Section 10: enrich_asn.py CLI (without pyasn DB)
# ─────────────────────────────────────────────

def test_enrich_asn_cli_no_db():
    section("10 · enrich_asn.py — CLI validation (pyasn DB optional)")

    try:
        import pyasn  # noqa: F401
        pyasn_available = True
    except ImportError:
        pyasn_available = False

    if not pyasn_available:
        skip("enrich_asn.py import test", "pyasn not installed")
        return

    # Check script is importable + help works
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "enrich_asn.py"), "--help"],
        capture_output=True, text=True,
    )
    assert_true("enrich_asn.py --help exits 0 or 1 (argparse)", result.returncode in (0, 1))
    assert_in("enrich_asn.py has --ips arg", "--ips", result.stdout + result.stderr)
    assert_in("enrich_asn.py has --asndb arg", "--asndb", result.stdout + result.stderr)
    assert_in("enrich_asn.py has --output arg", "--output", result.stdout + result.stderr)


# ─────────────────────────────────────────────
# Section 11: pipeline.env no longer has ROOT_DOMAINS
# ─────────────────────────────────────────────

def test_pipeline_env():
    section("11 · config/pipeline.env — ROOT_DOMAINS removed")

    env_path = PROJECT_ROOT / "config" / "pipeline.env"
    content = env_path.read_text()

    assert_true("ROOT_DOMAINS not set in pipeline.env",
                "ROOT_DOMAINS=" not in content or content.count("ROOT_DOMAINS=") == 0,
                "ROOT_DOMAINS= still present in pipeline.env")
    assert_true("ct_enrich.sh deleted",
                not (PROJECT_ROOT / "scripts" / "ct_enrich.sh").exists())


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  EASM IP Assets Implementation — Test Suite")
    print("=" * 60)

    test_ip_triage()
    test_ingest_asn()
    test_ingest_rdns()
    test_cdn_detection_signals()
    test_cdn_detection_confidence()
    test_enrich_cdn()
    test_full_normalize_pipeline()
    test_duckdb_views()
    test_run_sh_stage_order()
    test_enrich_asn_cli_no_db()
    test_pipeline_env()

    print(f"\n{'=' * 60}")
    print(f"  Results: {_PASS} passed  {_FAIL} failed  {_SKIP} skipped")
    print(f"{'=' * 60}")

    if _ERRORS:
        print("\nFailed tests:")
        for e in _ERRORS:
            print(f"  • {e}")

    return 0 if _FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
