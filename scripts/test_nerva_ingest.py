#!/usr/bin/env python3
"""Unit tests for Nerva ingestion in normalize.py."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from normalize import AssetStore, read_jsonl, _parse_cpe_fields, _extract_os_hints, _parse_version_string


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SSH_RECORD = {
    "host": "10.0.0.1",
    "ip": "10.0.0.1",
    "port": 22,
    "protocol": "ssh",
    "transport": "tcp",
    "metadata": {
        "version": "OpenSSH 8.9p1",
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7",
    },
    "cpe": "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
    "security_findings": [],
}

MYSQL_RECORD = {
    "host": "10.0.0.2",
    "port": 3306,
    "protocol": "mysql",
    "transport": "tcp",
    "metadata": {"server_version": "8.0.36"},
    "cpe": "cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*",
}

REDIS_RECORD = {
    "ip": "10.0.0.3",
    "port": 6379,
    "protocol": "redis",
    "transport": "tcp",
    "metadata": {},
}

MISCONFIG_RECORD = {
    "host": "10.0.0.4",
    "port": 22,
    "protocol": "ssh",
    "transport": "tcp",
    "metadata": {"banner": "SSH-2.0-OpenSSH_7.4"},
    "security_findings": [
        {"id": "weak-ssh-kex", "description": "Weak KEX algorithms", "severity": "medium"},
    ],
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_basic_ingestion():
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([SSH_RECORD, MYSQL_RECORD, REDIS_RECORD])

    assert "10.0.0.1" in store.assets
    assert "10.0.0.2" in store.assets
    assert "10.0.0.3" in store.assets

    svc = store.assets["10.0.0.1"]["services"][0]
    assert svc["service"] == "ssh"
    assert svc["port"] == 22
    assert svc["protocol"] == "tcp"
    assert svc["status"] == "success"
    assert "SSH-2.0-OpenSSH" in svc["banner"]

    print("PASS: test_basic_ingestion")


def test_cpe_fingerprint():
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([SSH_RECORD])

    fp = store.assets["10.0.0.1"]["services"][0]["fingerprint"]
    assert fp["vendor"] == "openbsd"
    assert fp["product"] == "openssh"
    assert fp["version"] == "8.9p1"
    assert fp["cpe23"].startswith("cpe:2.3:")
    assert fp["certainty"] == 0.95
    assert fp["source"] == "nerva"

    print("PASS: test_cpe_fingerprint")


def test_os_hints_from_banner():
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([SSH_RECORD])

    fp = store.assets["10.0.0.1"]["services"][0]["fingerprint"]
    assert fp["os_vendor"] == "Canonical"
    assert fp["os_product"] == "Ubuntu"

    print("PASS: test_os_hints_from_banner")


def test_version_only_certainty():
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([MYSQL_RECORD])

    fp = store.assets["10.0.0.2"]["services"][0]["fingerprint"]
    # Has CPE → certainty 0.95
    assert fp["certainty"] == 0.95
    assert fp["product"] == "mysql"

    print("PASS: test_version_only_certainty")


def test_no_metadata_certainty():
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([REDIS_RECORD])

    fp = store.assets["10.0.0.3"]["services"][0]["fingerprint"]
    # No CPE, no version_str → certainty 0.8
    assert fp["certainty"] == 0.8

    print("PASS: test_no_metadata_certainty")


def test_security_findings_ingested():
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([MISCONFIG_RECORD])

    findings = store.assets["10.0.0.4"]["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["source"] == "nerva_misconfig"
    assert f["template_id"] == "weak-ssh-kex"
    assert f["severity"] == "medium"
    assert "10.0.0.4:22" in f["matched_at"]

    print("PASS: test_security_findings_ingested")


def test_ip_field_fallback():
    """host field absent — falls back to ip."""
    record = {
        "ip": "10.0.0.5",
        "port": 443,
        "protocol": "http",
        "transport": "tcp",
        "metadata": {},
    }
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([record])
    assert "10.0.0.5" in store.assets

    print("PASS: test_ip_field_fallback")


def test_open_ports_populated():
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([SSH_RECORD])

    ports = store.assets["10.0.0.1"]["network"]["open_ports"]
    assert any(p["port"] == 22 for p in ports)

    print("PASS: test_open_ports_populated")


def test_dedup_open_ports():
    """Calling ingest_nerva twice for same port should not duplicate open_ports."""
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([SSH_RECORD, SSH_RECORD])

    ports = store.assets["10.0.0.1"]["network"]["open_ports"]
    port22 = [p for p in ports if p["port"] == 22]
    assert len(port22) == 1

    print("PASS: test_dedup_open_ports")


def test_summary_counts_services():
    store = AssetStore(scan_id="test_001")
    store.ingest_nerva([SSH_RECORD, MYSQL_RECORD, REDIS_RECORD])

    s = store.summary()
    assert s["total_services"] == 3
    # SSH and MySQL have CPE → with_fingerprints = 2
    assert s["with_fingerprints"] == 2

    print("PASS: test_summary_counts_services")


def test_export_roundtrip():
    import json
    store = AssetStore(scan_id="test_002")
    store.ingest_nerva([SSH_RECORD])

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="wb") as f:
        tmp = f.name

    store.export_jsonl(tmp)
    records = read_jsonl(tmp)
    Path(tmp).unlink()

    assert len(records) == 1
    svc = records[0]["services"][0]
    assert "fingerprint" in svc
    assert svc["fingerprint"]["cpe23"] != ""
    assert svc["fingerprint"]["source"] == "nerva"

    print("PASS: test_export_roundtrip")


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

def test_parse_cpe_fields():
    v, p, ver = _parse_cpe_fields("cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*")
    assert v == "openbsd"
    assert p == "openssh"
    assert ver == "8.9p1"

    # Wildcard version
    v2, p2, ver2 = _parse_cpe_fields("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
    assert ver2 == ""

    # Empty / invalid
    v3, p3, ver3 = _parse_cpe_fields("")
    assert v3 == p3 == ver3 == ""

    v4, p4, ver4 = _parse_cpe_fields("not-a-cpe")
    assert v4 == ""

    print("PASS: test_parse_cpe_fields")


def test_extract_os_hints():
    v, p, ver = _extract_os_hints("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7")
    assert v == "Canonical"
    assert p == "Ubuntu"

    v2, p2, ver2 = _extract_os_hints("SSH-2.0-OpenSSH_7.4 Debian-10+deb9u7")
    assert p2 == "Debian"

    v3, p3, ver3 = _extract_os_hints("SSH-2.0-OpenSSH_7.4p1 el7_9")
    assert p3 == "CentOS"

    v4, p4, ver4 = _extract_os_hints("Windows Server 2019")
    assert p4 == "Windows"

    v5, p5, ver5 = _extract_os_hints("plain banner")
    assert p5 == ""

    v6, p6, ver6 = _extract_os_hints("")
    assert p6 == ""

    print("PASS: test_extract_os_hints")


def test_parse_version_string():
    p, v = _parse_version_string("OpenSSH 8.9p1", "ssh")
    assert p == "OpenSSH"
    assert v == "8.9p1"

    p2, v2 = _parse_version_string("nginx/1.25.0", "http")
    assert "nginx" in p2.lower() or v2 == "1.25.0"

    p3, v3 = _parse_version_string("just-text", "smtp")
    assert p3 == "just-text"
    assert v3 == ""

    print("PASS: test_parse_version_string")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_parse_cpe_fields()
    test_extract_os_hints()
    test_parse_version_string()
    test_basic_ingestion()
    test_cpe_fingerprint()
    test_os_hints_from_banner()
    test_version_only_certainty()
    test_no_metadata_certainty()
    test_security_findings_ingested()
    test_ip_field_fallback()
    test_open_ports_populated()
    test_dedup_open_ports()
    test_summary_counts_services()
    test_export_roundtrip()
    print("\nAll Nerva ingestion tests passed.")
