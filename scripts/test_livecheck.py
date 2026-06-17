#!/usr/bin/env python3
"""
EASM Pipeline — Livecheck Mode Tests

Unit tests for CNAME chain analysis, leaf domain detection, unavailability
tracking, 3rd-party NS classification, CDN detection, and scope action logic.

Usage:
    python3 -m pytest scripts/test_livecheck.py -v
    python3 scripts/test_livecheck.py
"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from livecheck import (  # noqa: E402
    analyze_cname_chains,
    check_resolution,
    classify_nameservers,
    detect_cdn_for_livecheck,
    identify_leaf_domains,
    update_unavailability,
    _scope_action,
)


class TestResolutionCheck(unittest.TestCase):
    def test_resolving_fqdn(self):
        dns = [{"host": "www.example.com", "a": ["1.2.3.4"], "aaaa": [], "cname": []}]
        result = check_resolution(dns)
        self.assertTrue(result["www.example.com"]["resolves"])

    def test_non_resolving_fqdn(self):
        dns = [{"host": "dead.example.com", "a": [], "aaaa": [], "cname": []}]
        result = check_resolution(dns)
        self.assertFalse(result["dead.example.com"]["resolves"])

    def test_aaaa_only(self):
        dns = [{"host": "v6.example.com", "a": [], "aaaa": ["2001:db8::1"], "cname": []}]
        result = check_resolution(dns)
        self.assertTrue(result["v6.example.com"]["resolves"])

    def test_missing_fqdn(self):
        result = check_resolution([])
        self.assertEqual(result, {})


class TestCDNDetection(unittest.TestCase):
    def test_cloudflare_cname(self):
        dns_info = {
            "cname": ["cdn.example.com.cdn.cloudflare.com"],
            "a": [],
        }
        result = detect_cdn_for_livecheck(dns_info, {})
        self.assertIsNotNone(result)
        self.assertEqual(result["provider"], "cloudflare")
        self.assertGreater(result["confidence"], 0)

    def test_cloudflare_cname_and_asn(self):
        dns_info = {
            "cname": ["cdn.example.com.cdn.cloudflare.com"],
            "a": ["104.16.1.1"],
        }
        asn_by_ip = {"104.16.1.1": {"asn": 13335}}
        result = detect_cdn_for_livecheck(dns_info, asn_by_ip)
        self.assertEqual(result["provider"], "cloudflare")
        self.assertGreaterEqual(result["confidence"], 0.7)

    def test_no_cdn(self):
        dns_info = {"cname": [], "a": ["10.0.0.1"]}
        result = detect_cdn_for_livecheck(dns_info, {})
        self.assertIsNone(result)


class TestCNAMEChainAnalysis(unittest.TestCase):
    def test_bloated_chain(self):
        resolution_map = {
            "app.example.com": {
                "cname": ["a.cdn.com", "b.cdn.com", "c.cdn.com", "d.cdn.com", "e.cdn.com"],
            }
        }
        result = analyze_cname_chains(resolution_map, depth_threshold=3)
        self.assertIn("app.example.com", result["bloated"])
        self.assertEqual(result["bloated"]["app.example.com"]["chain_depth"], 5)

    def test_normal_chain(self):
        resolution_map = {
            "app.example.com": {"cname": ["cdn.example.com"]},
        }
        result = analyze_cname_chains(resolution_map, depth_threshold=3)
        self.assertEqual(len(result["bloated"]), 0)

    def test_fan_in(self):
        resolution_map = {
            "a.example.com": {"cname": ["shared.cdn.com"]},
            "b.example.com": {"cname": ["shared.cdn.com"]},
            "c.example.com": {"cname": ["unique.cdn.com"]},
        }
        result = analyze_cname_chains(resolution_map, depth_threshold=10)
        self.assertIn("shared.cdn.com", result["fan_in"])
        self.assertEqual(len(result["fan_in"]["shared.cdn.com"]), 2)
        self.assertNotIn("unique.cdn.com", result["fan_in"])


class TestLeafDomainDetection(unittest.TestCase):
    def test_leaf_detection(self):
        fqdns = {
            "example.com",
            "sub.example.com",
            "deep.sub.example.com",
            "other.example.com",
        }
        leaves = identify_leaf_domains(fqdns)
        self.assertIn("deep.sub.example.com", leaves)
        self.assertIn("other.example.com", leaves)
        self.assertNotIn("example.com", leaves)  # has children
        self.assertNotIn("sub.example.com", leaves)  # has child deep.sub

    def test_all_leaves(self):
        fqdns = {"a.example.com", "b.other.com"}
        leaves = identify_leaf_domains(fqdns)
        self.assertEqual(leaves, fqdns)


class TestUnavailabilityTracking(unittest.TestCase):
    def test_new_unavailable(self):
        state = {}
        resolution_map = {"dead.example.com": {"resolves": False}}
        cmdb_fqdns = {"dead.example.com"}

        result = update_unavailability(state, resolution_map, cmdb_fqdns, "scan1", 30)
        self.assertIn("dead.example.com", result)
        self.assertEqual(result["dead.example.com"]["consecutive_scans_down"], 1)
        self.assertFalse(result["dead.example.com"]["recommend_remove"])

    def test_past_deadline(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=35)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        state = {
            "dead.example.com": {
                "first_unavailable": old_date,
                "consecutive_scans_down": 5,
                "last_scan_id": "scan_old",
            }
        }
        resolution_map = {"dead.example.com": {"resolves": False}}
        cmdb_fqdns = {"dead.example.com"}

        result = update_unavailability(state, resolution_map, cmdb_fqdns, "scan6", 30)
        self.assertTrue(result["dead.example.com"]["recommend_remove"])
        self.assertGreaterEqual(result["dead.example.com"]["days_unavailable"], 35)

    def test_recovery_clears_state(self):
        state = {
            "recovered.example.com": {
                "first_unavailable": "2026-01-01T00:00:00Z",
                "consecutive_scans_down": 3,
                "last_scan_id": "scan3",
            }
        }
        resolution_map = {"recovered.example.com": {"resolves": True}}
        cmdb_fqdns = {"recovered.example.com"}

        result = update_unavailability(state, resolution_map, cmdb_fqdns, "scan4", 30)
        self.assertNotIn("recovered.example.com", result)
        self.assertNotIn("recovered.example.com", state)

    def test_state_persistence(self):
        state = {}
        resolution_map = {"down.example.com": {"resolves": False}}
        cmdb_fqdns = {"down.example.com"}

        update_unavailability(state, resolution_map, cmdb_fqdns, "scan1", 30)
        self.assertIn("down.example.com", state)
        self.assertEqual(state["down.example.com"]["consecutive_scans_down"], 1)

        # Second scan
        update_unavailability(state, resolution_map, cmdb_fqdns, "scan2", 30)
        self.assertEqual(state["down.example.com"]["consecutive_scans_down"], 2)


class TestNameserverClassification(unittest.TestCase):
    def test_cloudflare_ns(self):
        dns_info = {"ns": ["anna.ns.cloudflare.com", "bob.ns.cloudflare.com"]}
        result = classify_nameservers(dns_info, {"example.com"})
        self.assertEqual(result["ns_provider"], "cloudflare")
        self.assertTrue(result["ns_is_third_party"])

    def test_first_party_ns(self):
        dns_info = {"ns": ["ns1.example.com", "ns2.example.com"]}
        result = classify_nameservers(dns_info, {"example.com"})
        self.assertFalse(result["ns_is_third_party"])

    def test_route53_ns(self):
        dns_info = {"ns": ["ns-123.awsdns-45.net", "ns-678.awsdns-90.com"]}
        result = classify_nameservers(dns_info, {"example.com"})
        self.assertEqual(result["ns_provider"], "route53")
        self.assertTrue(result["ns_is_third_party"])

    def test_empty_ns(self):
        dns_info = {"ns": []}
        result = classify_nameservers(dns_info, {"example.com"})
        self.assertIsNone(result["ns_provider"])
        self.assertIsNone(result["ns_is_third_party"])


class TestScopeAction(unittest.TestCase):
    def test_remove(self):
        unavail = {"recommend_remove": True, "days_unavailable": 35}
        action = _scope_action(False, False, unavail, True, None)
        self.assertEqual(action, "remove")

    def test_exclude_cdn(self):
        action = _scope_action(True, True, None, False, None)
        self.assertEqual(action, "exclude_cdn")

    def test_review_remove_leaf(self):
        action = _scope_action(False, False, None, True, None)
        self.assertEqual(action, "review_remove")

    def test_keep(self):
        action = _scope_action(True, False, None, False, None)
        self.assertEqual(action, "keep")

    def test_monitor_unresolved(self):
        action = _scope_action(False, False, None, False, None)
        self.assertEqual(action, "monitor")

    def test_review_cname_bloat(self):
        bloat = {"chain_depth": 5, "cname_chain": ["a", "b", "c", "d", "e"]}
        action = _scope_action(True, False, None, False, bloat)
        self.assertEqual(action, "review_cname_bloat")


class TestEndToEnd(unittest.TestCase):
    """Integration test: write synthetic inputs, run livecheck, validate output."""

    def test_full_run(self):
        import tempfile
        from livecheck import run_livecheck, _json_dumps

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Create synthetic dns.jsonl
            dns_data = [
                {"host": "alive.example.com", "a": ["1.2.3.4"], "aaaa": [],
                 "cname": [], "ns": ["ns1.example.com"], "status_code": "NOERROR"},
                {"host": "cdn.example.com", "a": ["104.16.1.1"], "aaaa": [],
                 "cname": ["cdn.example.com.cdn.cloudflare.com"],
                 "ns": ["anna.ns.cloudflare.com"], "status_code": "NOERROR"},
                {"host": "bloated.example.com", "a": ["5.6.7.8"], "aaaa": [],
                 "cname": ["a.x.com", "b.x.com", "c.x.com", "d.x.com"],
                 "ns": ["ns1.example.com"], "status_code": "NOERROR"},
            ]
            dns_path = tmpdir / "dns.jsonl"
            with open(dns_path, "wb") as f:
                for rec in dns_data:
                    f.write(_json_dumps(rec) + b"\n")

            # Create synthetic asn.jsonl
            asn_data = [
                {"ip": "104.16.1.1", "asn": 13335, "org": "CLOUDFLARENET"},
            ]
            asn_path = tmpdir / "asn.jsonl"
            with open(asn_path, "wb") as f:
                for rec in asn_data:
                    f.write(_json_dumps(rec) + b"\n")

            # Create synthetic CMDB
            cmdb_path = tmpdir / "cmdb.csv"
            with open(cmdb_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["ci_id", "fqdn", "ip", "owner"])
                writer.writeheader()
                writer.writerow({"ci_id": "CI-001", "fqdn": "alive.example.com",
                                 "ip": "1.2.3.4", "owner": "team-a"})
                writer.writerow({"ci_id": "CI-002", "fqdn": "cdn.example.com",
                                 "ip": "", "owner": "team-b"})
                writer.writerow({"ci_id": "CI-003", "fqdn": "dead.example.com",
                                 "ip": "9.9.9.9", "owner": "team-c"})

            output_path = tmpdir / "report.jsonl"
            state_path = tmpdir / "state.json"

            # Build args namespace
            class Args:
                dns = str(dns_path)
                asn = str(asn_path)
                cmdb = str(cmdb_path)
                state = str(state_path)
                output = str(output_path)
                scan_id = "test_001"
                deadline_days = 30
                cname_depth_threshold = 3

            report = run_livecheck(Args())

            # Validate
            self.assertGreater(len(report), 0)

            by_fqdn = {r["fqdn"]: r for r in report}

            # alive.example.com should resolve and be kept
            self.assertTrue(by_fqdn["alive.example.com"]["resolves"])
            self.assertEqual(by_fqdn["alive.example.com"]["scope_action"], "keep")

            # cdn.example.com should be CDN-excluded
            self.assertTrue(by_fqdn["cdn.example.com"]["exclude_proposal"])
            self.assertEqual(by_fqdn["cdn.example.com"]["cdn_provider"], "cloudflare")

            # dead.example.com should not resolve
            self.assertFalse(by_fqdn["dead.example.com"]["resolves"])
            self.assertTrue(by_fqdn["dead.example.com"]["in_cmdb"])

            # bloated.example.com should have CNAME bloat
            self.assertTrue(by_fqdn["bloated.example.com"]["cname_bloated"])
            self.assertEqual(by_fqdn["bloated.example.com"]["cname_chain_depth"], 4)

            # State file should exist and track dead.example.com
            self.assertTrue(state_path.exists())
            with open(state_path) as f:
                state = json.load(f)
            self.assertIn("dead.example.com", state)


# Need csv import for the E2E test
import csv  # noqa: E402


if __name__ == "__main__":
    unittest.main()
