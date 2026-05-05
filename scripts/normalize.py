#!/usr/bin/env python3
"""
EASM Pipeline — Asset Normalizer

Merges outputs from dnsx, naabu, httpx, tlsx, nerva, zgrab2, nuclei, and subzy
into a single unified asset record per FQDN, keyed by the data model
defined in the EASM plan (§4).

Usage:
    python3 normalize.py \
        --dns dns.jsonl --ports ports.jsonl --http httpx.jsonl \
        --tls tls.jsonl --nerva nerva.jsonl --nuclei nuclei.jsonl \
        --subzy subzy.json --cmdb cmdb_export.csv \
        --output assets.jsonl --scan-id 20260419_021509
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import orjson


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: str) -> list[dict]:
    """Read a JSONL file, skipping malformed lines."""
    records = []
    p = Path(path)
    if not p.exists():
        return records
    with open(p, "rb") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(orjson.loads(line))
            except orjson.JSONDecodeError:
                print(f"WARN: Skipping malformed JSON at {path}:{line_no}", file=sys.stderr)
    return records


def read_json_file(path: str) -> Any:
    """Read a single JSON file."""
    p = Path(path)
    if not p.exists():
        return None
    with open(p, "rb") as f:
        return orjson.loads(f.read())


def read_cmdb_csv(path: str) -> dict[str, dict]:
    """
    Read CMDB CSV export. Expected columns (flexible):
      ci_id, fqdn, ip, owner, cost_center, environment, description
    Returns dict keyed by lowercase FQDN.
    """
    result = {}
    p = Path(path)
    if not p.exists():
        return result
    with open(p, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fqdn = (row.get("fqdn") or row.get("hostname") or row.get("name") or "").strip().lower()
            if not fqdn:
                continue
            result[fqdn] = {
                "ci_id": row.get("ci_id", "").strip(),
                "ip": row.get("ip", "").strip(),
                "owner": row.get("owner", "").strip(),
                "cost_center": row.get("cost_center", "").strip(),
                "environment": row.get("environment", "").strip(),
                "description": row.get("description", "").strip(),
            }
    return result


# Shared hosting detection: known provider ASNs
_HOSTING_ASNS: dict[int, str] = {
    26496: "godaddy",
    46606: "unified_layer",   # Bluehost, HostGator
    26347: "dreamhost",
    64476: "siteground",
    55293: "a2hosting",
    46475: "inmotionhosting",
    6315:  "wpengine",
    22244: "namecheap",
    19871: "networksolutions",
    36351: "softlayer",       # IBM Cloud shared
}

# Shared hosting detection: (header_name, regex_pattern, provider)
_HOSTING_HEADERS: list[tuple[str, str, str]] = [
    ("x-powered-by",    r"(?i)cpanel",     "cpanel"),
    ("server",          r"(?i)litespeed",  "litespeed"),
    ("x-hacker",        r".",              "wordpress_com"),
    ("x-kinsta-cache",  r".",              "kinsta"),
    ("x-wpe-nonce",     r".",              "wpengine"),
    ("x-pantheon-styx", r".",              "pantheon"),
]


class AssetStore:
    """Accumulates data per FQDN and builds unified asset records."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.timestamp = now_iso()
        self.assets: dict[str, dict] = {}

    def _ensure(self, fqdn: str) -> dict:
        fqdn = fqdn.lower().strip().rstrip(".")
        if not fqdn:
            return {}
        if fqdn not in self.assets:
            self.assets[fqdn] = {
                "fqdn": fqdn,
                "scan_id": self.scan_id,
                "first_seen": self.timestamp,
                "last_seen": self.timestamp,
                "source": [],
                "tags": [],
                "dns": {
                    "a": [],
                    "aaaa": [],
                    "cname_chain": [],
                    "ns": [],
                    "mx": [],
                    "txt": [],
                    "wildcard": False,
                    "ptr": [],
                },
                "network": {
                    "asn": {"number": None, "org": None, "country": None},
                    "cdn": None,
                    "cdn_detection": None,
                    "shared_hosting": None,
                    "open_ports": [],
                },
                "web": [],
                "tls": [],
                "services": [],
                "findings": [],
                "cmdb": {
                    "matched_ci": None,
                    "match_basis": [],
                    "in_cmdb": False,
                    "gap_type": None,
                },
            }
        return self.assets[fqdn]

    def _add_source(self, asset: dict, source: str):
        if source not in asset["source"]:
            asset["source"].append(source)

    def _add_tag(self, asset: dict, tag: str):
        if tag not in asset["tags"]:
            asset["tags"].append(tag)

    # --- DNS ---
    def ingest_dns(self, records: list[dict]):
        for rec in records:
            host = rec.get("host", "")
            if not host:
                continue
            asset = self._ensure(host)
            if not asset:
                continue
            self._add_source(asset, "dns")

            dns = asset["dns"]

            # A records
            for a in _as_list(rec.get("a")):
                if a and a not in dns["a"]:
                    dns["a"].append(a)

            # AAAA records
            for aaaa in _as_list(rec.get("aaaa")):
                if aaaa and aaaa not in dns["aaaa"]:
                    dns["aaaa"].append(aaaa)

            # CNAME
            cname = rec.get("cname")
            if cname:
                chain = _as_list(cname)
                for c in chain:
                    if c and c not in dns["cname_chain"]:
                        dns["cname_chain"].append(c)

            # NS
            for ns in _as_list(rec.get("ns")):
                if ns and ns not in dns["ns"]:
                    dns["ns"].append(ns)

            # MX
            for mx in _as_list(rec.get("mx")):
                if mx and mx not in dns["mx"]:
                    dns["mx"].append(mx)

            # TXT
            for txt in _as_list(rec.get("txt")):
                if txt and txt not in dns["txt"]:
                    dns["txt"].append(txt)

    # --- ASN ---
    def ingest_asn(self, records: list[dict]):
        """Ingest ASN enrichment JSONL. Maps IPs to existing FQDN assets."""
        ip_to_asn: dict[str, dict] = {}
        for rec in records:
            ip = rec.get("ip", "")
            if ip and rec.get("asn"):
                ip_to_asn[ip] = rec

        # Enrich existing assets that have resolved IPs
        for fqdn, asset in self.assets.items():
            if asset["network"]["asn"]["number"]:
                continue  # already enriched (e.g. from httpx)
            for ip in asset["dns"]["a"]:
                if ip in ip_to_asn:
                    asn_rec = ip_to_asn[ip]
                    asset["network"]["asn"] = {
                        "number": asn_rec["asn"],
                        "org": asn_rec.get("org", ""),
                        "country": None,
                    }
                    self._add_source(asset, "pyasn")
                    break

        # Create asset records for standalone IPs (those not behind any FQDN)
        fqdn_ips: set[str] = set()
        for asset in self.assets.values():
            fqdn_ips.update(asset["dns"]["a"])

        for ip, asn_rec in ip_to_asn.items():
            if ip not in fqdn_ips:
                asset = self._ensure(ip)
                if asset:
                    asset["dns"]["a"] = [ip]
                    asset["network"]["asn"] = {
                        "number": asn_rec["asn"],
                        "org": asn_rec.get("org", ""),
                        "country": None,
                    }
                    self._add_source(asset, "pyasn")
                    self._add_tag(asset, "ip_only")

    # --- Reverse DNS ---
    def ingest_rdns(self, records: list[dict]):
        """Ingest reverse DNS (PTR) records. Maps IPs back to FQDN assets."""
        ip_to_ptr: dict[str, list[str]] = {}
        for rec in records:
            host = rec.get("host", "")  # IP that was queried
            ptrs = _as_list(rec.get("ptr"))
            if host and ptrs:
                ip_to_ptr[host] = [p.rstrip(".").lower() for p in ptrs if p]

        for fqdn, asset in self.assets.items():
            for ip in asset["dns"]["a"]:
                if ip in ip_to_ptr:
                    asset["dns"]["ptr"].append({"ip": ip, "ptrs": ip_to_ptr[ip]})
                    self._add_source(asset, "rdns")

    # --- CDN ---
    def enrich_cdn(self):
        """Run multi-signal CDN detection on all assets."""
        from detect_cdn import CDNDetector
        detector = CDNDetector()

        for fqdn, asset in self.assets.items():
            existing_cdn = asset["network"].get("cdn")
            result = detector.detect(asset)
            if result:
                if not existing_cdn or existing_cdn in ("true", "True", True):
                    asset["network"]["cdn"] = result["provider"]
                asset["network"]["cdn_detection"] = {
                    "provider": result["provider"],
                    "confidence": result["confidence"],
                    "signals": result["signals"],
                }
                self._add_tag(asset, "cdn")
            elif not existing_cdn:
                asset["network"]["cdn"] = None
                asset["network"]["cdn_detection"] = None

    # --- Shared hosting ---
    def enrich_shared_hosting(self):
        """Detect shared hosting via IP density, ASN, HTTP headers, and TLS SAN signals."""
        # Build ip → [fqdns] map, skipping CDN assets (CDN IPs are not shared hosting)
        ip_to_fqdns: dict[str, list[str]] = {}
        for fqdn, asset in self.assets.items():
            if asset["network"].get("cdn"):
                continue
            for ip in asset["dns"]["a"]:
                ip_to_fqdns.setdefault(ip, []).append(fqdn)

        def _reg(fqdn: str) -> str:
            parts = fqdn.rstrip(".").split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn

        for fqdn, asset in self.assets.items():
            # CDN assets are not shared hosting
            if asset["network"].get("cdn"):
                asset["network"]["shared_hosting"] = None
                continue

            signals: list[str] = []

            # Signal 1: IP density — count peers from different registrable domains
            self_reg = _reg(fqdn)
            best_count = 0
            for ip in asset["dns"]["a"]:
                cross = [f for f in ip_to_fqdns.get(ip, []) if f != fqdn and _reg(f) != self_reg]
                if len(cross) > best_count:
                    best_count = len(cross)
            if best_count >= 1:
                signals.append(f"ip_density:{best_count}")

            # Signal 2: known shared-hosting ASN
            asn_num = asset["network"]["asn"].get("number")
            if asn_num is not None:
                provider = _HOSTING_ASNS.get(int(asn_num))
                if provider:
                    signals.append(f"asn:{provider}")

            # Signal 3: HTTP response headers fingerprinting hosting panels
            seen: set[str] = set()
            for web_entry in asset["web"]:
                headers = web_entry.get("headers_of_interest", {})
                for hdr, pattern, provider in _HOSTING_HEADERS:
                    val = headers.get(hdr, "")
                    if val and re.search(pattern, val) and provider not in seen:
                        seen.add(provider)
                        signals.append(f"header:{provider}")

            # Signal 4: TLS cert covering 3+ distinct registrable domains (shared cert)
            for tls_entry in asset["tls"]:
                registrable: set[str] = set()
                for san in tls_entry.get("sans", []):
                    parts = san.lstrip("*.").rstrip(".").split(".")
                    if len(parts) >= 2:
                        registrable.add(".".join(parts[-2:]))
                if len(registrable) >= 3:
                    signals.append(f"tls_san:{len(registrable)}")
                    break

            if signals:
                signal_types = {s.split(":")[0] for s in signals}
                asset["network"]["shared_hosting"] = {
                    "detected": True,
                    "confidence": round(min(1.0, len(signal_types) * 0.35), 2),
                    "cohosted_count": best_count,
                    "signals": signals,
                }
                self._add_tag(asset, "shared_hosting")
            else:
                asset["network"]["shared_hosting"] = None

    # --- Ports ---
    def ingest_ports(self, records: list[dict]):
        for rec in records:
            host = rec.get("host") or rec.get("ip", "")
            port = rec.get("port")
            if not host or port is None:
                continue
            asset = self._ensure(host)
            if not asset:
                continue
            self._add_source(asset, "naabu")

            port_entry = {
                "port": port,
                "protocol": rec.get("protocol", "tcp"),
                "service": None,
                "banner": None,
            }
            # Avoid duplicate ports
            existing_ports = {p["port"] for p in asset["network"]["open_ports"]}
            if port not in existing_ports:
                asset["network"]["open_ports"].append(port_entry)

    # --- HTTP ---
    def ingest_http(self, records: list[dict]):
        for rec in records:
            host = rec.get("input", "").split(":")[0] if ":" in rec.get("input", "") else rec.get("host", "")
            if not host:
                # Try to extract from url
                url = rec.get("url", "")
                if "://" in url:
                    host = url.split("://")[1].split("/")[0].split(":")[0]
            if not host:
                continue

            asset = self._ensure(host)
            if not asset:
                continue
            self._add_source(asset, "httpx")
            self._add_tag(asset, "web")

            port = rec.get("port", 443)
            scheme = "https" if port in (443, 8443, 4443, 9443) else "http"
            if rec.get("url", "").startswith("https"):
                scheme = "https"

            web_entry = {
                "port": port,
                "scheme": scheme,
                "url": rec.get("url", ""),
                "final_url": rec.get("final_url") or rec.get("location", ""),
                "status_code": rec.get("status_code") or rec.get("status-code"),
                "title": rec.get("title", ""),
                "server": rec.get("webserver") or rec.get("server", ""),
                "content_type": rec.get("content_type") or rec.get("content-type", ""),
                "content_length": rec.get("content_length") or rec.get("content-length"),
                "response_time_ms": rec.get("response_time") or rec.get("time"),
                "tech": _parse_tech(rec.get("tech") or rec.get("technologies")),
                "favicon_mmh3": rec.get("favicon"),
                "body_sha256": rec.get("body_sha256") or (rec.get("hash", {}) or {}).get("body_sha256"),
                "headers_of_interest": _extract_headers(rec),
                "redirect_chain": _as_list(rec.get("chain")),
                "screenshot_path": rec.get("screenshot_path") or rec.get("screenshot"),
                "http2": rec.get("http2", False),
                "websocket": rec.get("websocket", False),
                "method": rec.get("method", "GET"),
                "jarm": rec.get("jarm", ""),
                "probe_status": rec.get("probe_status", ""),
            }
            asset["web"].append(web_entry)

            # Enrich network from httpx
            if rec.get("asn"):
                asn_data = rec["asn"] if isinstance(rec["asn"], dict) else {}
                if asn_data:
                    asset["network"]["asn"] = {
                        "number": asn_data.get("as_number"),
                        "org": asn_data.get("as_name") or asn_data.get("as_org"),
                        "country": asn_data.get("as_country"),
                    }
            if rec.get("cdn_name"):
                asset["network"]["cdn"] = rec["cdn_name"]
            elif rec.get("cdn"):
                asset["network"]["cdn"] = str(rec["cdn"])

            # IP from httpx
            if rec.get("host") and rec["host"] not in asset["dns"]["a"]:
                ip = rec.get("a") or rec.get("host_ip")
                if ip:
                    ips = _as_list(ip)
                    for i in ips:
                        if i and i not in asset["dns"]["a"]:
                            asset["dns"]["a"].append(i)

            # CNAME from httpx
            if rec.get("cname"):
                for c in _as_list(rec["cname"]):
                    if c and c not in asset["dns"]["cname_chain"]:
                        asset["dns"]["cname_chain"].append(c)

    # --- TLS ---
    def ingest_tls(self, records: list[dict]):
        for rec in records:
            host = rec.get("host", "").split(":")[0]
            if not host:
                continue
            asset = self._ensure(host)
            if not asset:
                continue
            self._add_source(asset, "tlsx")

            port = rec.get("port", 443)
            tls_entry = {
                "port": port,
                "version": rec.get("tls_version") or rec.get("version", ""),
                "cipher": rec.get("cipher", ""),
                "jarm": rec.get("jarm", ""),
                "ja3s": rec.get("ja3s", ""),
                "issuer": _extract_cert_field(rec, "issuer_dn") or _extract_cert_field(rec, "issuer"),
                "subject": _extract_cert_field(rec, "subject_dn") or _extract_cert_field(rec, "subject"),
                "sans": _as_list(rec.get("san") or rec.get("subject_an")),
                "not_before": rec.get("not_before", ""),
                "not_after": rec.get("not_after", ""),
                "days_to_expiry": _calc_days_to_expiry(rec.get("not_after", "")),
                "key_algo": rec.get("key_algo", ""),
                "key_size": rec.get("key_size"),
                "self_signed": rec.get("self_signed", False),
                "expired": rec.get("expired", False),
                "mismatched": rec.get("mismatched", False),
                "revoked": rec.get("revoked", False),
                "untrusted": rec.get("untrusted", False),
                "wildcard_cert": rec.get("wildcard_cert", False),
                "serial": rec.get("serial", ""),
                "fingerprint_sha256": rec.get("fingerprint_hash", {}).get("sha256", "") if isinstance(rec.get("fingerprint_hash"), dict) else "",
            }
            asset["tls"].append(tls_entry)

            # Harvest SANs as additional discovery
            for san in tls_entry["sans"]:
                san = san.lower().strip().lstrip("*.")
                if san and san != host:
                    san_asset = self._ensure(san)
                    if san_asset:
                        self._add_source(san_asset, "tls_san")

    # --- zgrab2 ---
    def ingest_zgrab(self, records: list[dict], module: str):
        for rec in records:
            ip = rec.get("ip", "")
            domain = rec.get("domain", "")
            host = domain or ip
            if not host:
                continue

            asset = self._ensure(host)
            if not asset:
                continue
            self._add_source(asset, f"zgrab2_{module}")

            data = rec.get("data", {}).get(module, {})
            status = data.get("status", "unknown")

            banner = ""
            if module == "ssh":
                server_id = data.get("result", {}).get("server_id", {})
                if isinstance(server_id, dict):
                    banner = server_id.get("raw", "")
                elif isinstance(server_id, str):
                    banner = server_id
            elif module == "ftp":
                banner = data.get("result", {}).get("banner", "")
            elif module == "smtp":
                banner = data.get("result", {}).get("banner", "")

            port = _module_default_port(module)
            service_entry = {
                "port": port,
                "protocol": "tcp",
                "transport": "tcp",
                "service": module,
                "status": status,
                "banner": banner,
                "fingerprint": {
                    "vendor": "",
                    "product": module,
                    "version": "",
                    "cpe23": "",
                    "os_vendor": "",
                    "os_product": "",
                    "os_version": "",
                    "certainty": 0.3,
                    "source": "zgrab2",
                },
                "metadata": {},
                "raw": data.get("result", {}),
            }
            asset["services"].append(service_entry)

            # Update open_ports if not already there
            existing_ports = {p["port"] for p in asset["network"]["open_ports"]}
            if port not in existing_ports:
                asset["network"]["open_ports"].append({
                    "port": port,
                    "protocol": "tcp",
                    "service": module,
                    "banner": banner,
                })

    # --- Nerva ---
    def ingest_nerva(self, records: list[dict]):
        """Ingest nerva JSONL output.

        Nerva JSON format per line:
            {"host":"x.x.x.x","ip":"x.x.x.x","port":22,"protocol":"ssh",
             "transport":"tcp","metadata":{...},"security_findings":[...]}

        All service-specific detail (version, banner) lives in metadata
        under protocol-specific keys. security_findings is present only
        when nerva was run with --misconfigs.
        """
        for rec in records:
            host = rec.get("host") or rec.get("ip", "")
            port = rec.get("port")
            if not host or port is None:
                continue

            asset = self._ensure(host)
            if not asset:
                continue
            self._add_source(asset, "nerva")

            protocol = (rec.get("protocol") or "").lower()
            transport = (rec.get("transport") or "tcp").lower()
            metadata = rec.get("metadata") or {}

            # version/banner: try common metadata keys across protocols
            version_str = (
                metadata.get("version")
                or metadata.get("server_version")
                or metadata.get("banner")
                or ""
            )
            banner = (
                metadata.get("banner")
                or metadata.get("server_version")
                or version_str
            )

            cpe = rec.get("cpe") or metadata.get("cpe") or ""
            vendor, product, version = _parse_cpe_fields(cpe)
            if not product and version_str:
                product, version = _parse_version_string(version_str, protocol)

            os_vendor, os_product, os_version = _extract_os_hints(banner or version_str)

            if cpe:
                certainty = 0.95
            elif version_str:
                certainty = 0.7
            else:
                certainty = 0.8

            service_entry = {
                "port": port,
                "protocol": transport,
                "transport": transport,
                "service": protocol,
                "status": "success" if protocol else "unknown",
                "banner": banner,
                "fingerprint": {
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                    "cpe23": cpe,
                    "os_vendor": os_vendor,
                    "os_product": os_product,
                    "os_version": os_version,
                    "certainty": certainty,
                    "source": "nerva",
                },
                "metadata": metadata,
                "raw": {},
            }
            asset["services"].append(service_entry)

            existing_ports = {p["port"] for p in asset["network"]["open_ports"]}
            if port not in existing_ports:
                asset["network"]["open_ports"].append({
                    "port": port,
                    "protocol": transport,
                    "service": protocol,
                    "banner": banner,
                })

            # Security misconfigurations from --misconfigs flag
            for sf in rec.get("security_findings") or []:
                finding = {
                    "source": "nerva_misconfig",
                    "template_id": sf.get("id", ""),
                    "name": sf.get("description", sf.get("id", "")),
                    "severity": sf.get("severity", "info"),
                    "matched_at": f"{host}:{port}",
                    "evidence": sf.get("evidence", ""),
                    "timestamp": self.timestamp,
                }
                asset["findings"].append(finding)
                self._add_source(asset, "nerva_misconfigs")

    # --- Nuclei ---
    def ingest_nuclei(self, records: list[dict]):
        for rec in records:
            host = rec.get("host", "")
            # Nuclei puts the full URL in "host" (e.g. "https://example.com:8443")
            if "://" in host:
                host = host.split("://")[1].split("/")[0].split(":")[0]
            if not host:
                matched = rec.get("matched-at", "") or rec.get("matched_at", "")
                if "://" in matched:
                    host = matched.split("://")[1].split("/")[0].split(":")[0]
            if not host:
                continue

            asset = self._ensure(host)
            if not asset:
                continue
            self._add_source(asset, "nuclei")

            info = rec.get("info", {})
            finding = {
                "source": "nuclei",
                "template_id": rec.get("template-id") or rec.get("template_id", ""),
                "template": rec.get("template", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "matched_at": rec.get("matched-at") or rec.get("matched_at", ""),
                "extracted_results": rec.get("extracted-results") or rec.get("extracted_results", []),
                "tags": info.get("tags", []) if isinstance(info.get("tags"), list) else str(info.get("tags", "")).split(","),
                "description": info.get("description", ""),
                "curl_command": rec.get("curl-command", ""),
                "timestamp": rec.get("timestamp", self.timestamp),
            }
            asset["findings"].append(finding)

    # --- Subzy ---
    def ingest_subzy(self, data: Any):
        if data is None:
            return
        entries = data if isinstance(data, list) else [data]
        for rec in entries:
            is_vulnerable = rec.get("vulnerable", False) or rec.get("status") == "vulnerable"
            if not is_vulnerable:
                continue
            host = rec.get("subdomain") or rec.get("domain", "")
            if not host:
                continue
            asset = self._ensure(host)
            if not asset:
                continue
            self._add_source(asset, "subzy")

            service = rec.get("service") or rec.get("engine", "")
            finding = {
                "source": "subzy",
                "template_id": "subdomain-takeover",
                "name": f"Subdomain Takeover - {service or 'unknown'}",
                "severity": "high",
                "matched_at": host,
                "service": service,
                "cname": rec.get("cname", ""),
                "vulnerable": True,
                "timestamp": self.timestamp,
            }
            asset["findings"].append(finding)

    # --- CMDB reconciliation ---
    def reconcile_cmdb(self, cmdb: dict[str, dict]):
        if not cmdb:
            return

        # Build reverse-lookup maps for IP and SAN matching
        cmdb_ips: dict[str, str] = {}
        for fqdn, ci in cmdb.items():
            if ci.get("ip"):
                cmdb_ips[ci["ip"]] = fqdn

        for fqdn, asset in self.assets.items():
            match_basis = []

            # 1. Exact FQDN match
            if fqdn in cmdb:
                ci = cmdb[fqdn]
                asset["cmdb"]["matched_ci"] = ci.get("ci_id")
                match_basis.append("fqdn")
                asset["cmdb"]["in_cmdb"] = True

            # 2. IP match
            if not asset["cmdb"]["in_cmdb"]:
                for ip in asset["dns"]["a"]:
                    if ip in cmdb_ips:
                        ci_fqdn = cmdb_ips[ip]
                        ci = cmdb[ci_fqdn]
                        asset["cmdb"]["matched_ci"] = ci.get("ci_id")
                        match_basis.append("ip")
                        asset["cmdb"]["in_cmdb"] = True
                        break

            # 3. TLS SAN match
            if not asset["cmdb"]["in_cmdb"]:
                for tls_rec in asset["tls"]:
                    for san in tls_rec.get("sans", []):
                        san_clean = san.lower().strip().lstrip("*.")
                        if san_clean in cmdb:
                            ci = cmdb[san_clean]
                            asset["cmdb"]["matched_ci"] = ci.get("ci_id")
                            match_basis.append("cert_san")
                            asset["cmdb"]["in_cmdb"] = True
                            break
                    if asset["cmdb"]["in_cmdb"]:
                        break

            asset["cmdb"]["match_basis"] = match_basis

            # Determine gap type
            if not asset["cmdb"]["in_cmdb"]:
                # Is it a live asset?
                has_web = len(asset["web"]) > 0
                has_ports = len(asset["network"]["open_ports"]) > 0
                has_dns = len(asset["dns"]["a"]) > 0 or len(asset["dns"]["aaaa"]) > 0

                if has_web or has_ports:
                    asset["cmdb"]["gap_type"] = "shadow_it"
                elif has_dns:
                    asset["cmdb"]["gap_type"] = "unmanaged"
                else:
                    asset["cmdb"]["gap_type"] = "orphan_cert"

        # Check for stale CIs (in CMDB but not discovered or dead)
        discovered_fqdns = set(self.assets.keys())
        for cmdb_fqdn, ci in cmdb.items():
            if cmdb_fqdn not in discovered_fqdns:
                # Create a minimal asset record for stale CI
                asset = self._ensure(cmdb_fqdn)
                if asset:
                    self._add_source(asset, "cmdb")
                    self._add_tag(asset, "stale_ci")
                    asset["cmdb"]["matched_ci"] = ci.get("ci_id")
                    asset["cmdb"]["in_cmdb"] = True
                    asset["cmdb"]["gap_type"] = "stale_ci"

    # --- Export ---
    def export_jsonl(self, path: str):
        with open(path, "wb") as f:
            for fqdn in sorted(self.assets.keys()):
                asset = self.assets[fqdn]
                # Sort open_ports by port number
                asset["network"]["open_ports"].sort(key=lambda p: p.get("port", 0))
                f.write(orjson.dumps(asset, option=orjson.OPT_APPEND_NEWLINE))

    def summary(self) -> dict:
        total = len(self.assets)
        with_web = sum(1 for a in self.assets.values() if a["web"])
        with_tls = sum(1 for a in self.assets.values() if a["tls"])
        with_findings = sum(1 for a in self.assets.values() if a["findings"])
        in_cmdb = sum(1 for a in self.assets.values() if a["cmdb"]["in_cmdb"])
        shadow_it = sum(1 for a in self.assets.values() if a["cmdb"]["gap_type"] == "shadow_it")
        stale_ci = sum(1 for a in self.assets.values() if a["cmdb"]["gap_type"] == "stale_ci")
        total_findings = sum(len(a["findings"]) for a in self.assets.values())
        sev_counts = defaultdict(int)
        for a in self.assets.values():
            for f in a["findings"]:
                sev_counts[f.get("severity", "unknown")] += 1

        total_services = sum(len(a.get("services", [])) for a in self.assets.values())
        with_fingerprints = sum(
            1 for a in self.assets.values()
            if any(s.get("fingerprint", {}).get("cpe23") for s in a.get("services", []))
        )

        return {
            "total_assets": total,
            "with_web": with_web,
            "with_tls": with_tls,
            "with_findings": with_findings,
            "in_cmdb": in_cmdb,
            "shadow_it": shadow_it,
            "stale_ci": stale_ci,
            "cmdb_gap_pct": round((shadow_it / total * 100) if total > 0 else 0, 1),
            "total_findings": total_findings,
            "findings_by_severity": dict(sev_counts),
            "total_services": total_services,
            "with_fingerprints": with_fingerprints,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_list(val: Any) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        return [val]
    return [val]


def _parse_tech(tech_data: Any) -> list[dict]:
    if not tech_data:
        return []
    techs = []
    if isinstance(tech_data, list):
        for t in tech_data:
            if isinstance(t, str):
                techs.append({"name": t, "version": None, "categories": []})
            elif isinstance(t, dict):
                techs.append({
                    "name": t.get("name", str(t)),
                    "version": t.get("version"),
                    "categories": _as_list(t.get("categories")),
                })
    elif isinstance(tech_data, dict):
        for name, info in tech_data.items():
            techs.append({
                "name": name,
                "version": info.get("version") if isinstance(info, dict) else None,
                "categories": [],
            })
    return techs


def _extract_headers(rec: dict) -> dict:
    """Extract security-relevant headers from httpx record."""
    headers = {}
    raw_headers = rec.get("header", {}) or {}
    if isinstance(raw_headers, str):
        parsed = {}
        for line in raw_headers.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                parsed[k.strip().lower()] = v.strip()
        raw_headers = parsed

    interesting = [
        "strict-transport-security",
        "content-security-policy",
        "x-powered-by",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "access-control-allow-origin",
        "set-cookie",
        # CDN detection headers
        "cf-ray",
        "cf-cache-status",
        "x-amz-cf-id",
        "x-amz-cf-pop",
        "x-akamai-transformed",
        "x-akamai-request-id",
        "x-served-by",
        "x-fastly-request-id",
        "x-azure-ref",
        "x-msedge-ref",
        "x-sucuri-id",
        "x-sucuri-cache",
        "x-cdn",
        "x-iinfo",
        "x-nf-request-id",
        "x-vercel-id",
        # Shared hosting fingerprints
        "server",
        "x-hacker",
        "x-kinsta-cache",
        "x-wpe-nonce",
        "x-pantheon-styx",
    ]
    for h in interesting:
        val = raw_headers.get(h)
        if val:
            headers[h] = val if isinstance(val, str) else str(val)

    return headers


def _extract_cert_field(rec: dict, field: str) -> str:
    val = rec.get(field)
    if isinstance(val, dict):
        # DN components
        parts = []
        for k, v in val.items():
            if v:
                parts.append(f"{k}={v}")
        return ", ".join(parts)
    return str(val) if val else ""


def _calc_days_to_expiry(not_after: str) -> int | None:
    if not not_after:
        return None
    try:
        from dateutil import parser as dateparser
        expiry = dateparser.parse(not_after)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        delta = expiry - datetime.now(timezone.utc)
        return delta.days
    except Exception:
        return None


def _module_default_port(module: str) -> int:
    ports = {
        "ssh": 22, "ftp": 21, "smtp": 25, "imap": 143, "pop3": 110,
        "mysql": 3306, "postgres": 5432, "redis": 6379, "mongodb": 27017,
        "mssql": 1433, "smb": 445, "telnet": 23,
    }
    return ports.get(module, 0)


def _parse_cpe_fields(cpe: str) -> tuple[str, str, str]:
    """Extract vendor, product, version from CPE 2.3 string."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return ("", "", "")
    parts = cpe.split(":")
    if len(parts) < 7:
        return ("", "", "")
    vendor = parts[3] if parts[3] != "*" else ""
    product = parts[4] if parts[4] != "*" else ""
    version = parts[5] if parts[5] != "*" else ""
    return (vendor, product, version)


def _parse_version_string(version_str: str, service: str) -> tuple[str, str]:
    """Best-effort (product, version) extraction from a free-form version string."""
    m = re.match(r'^(\S+?)[\s/_-]*([\d][\d.]*\S*)', version_str)
    if m:
        return (m.group(1), m.group(2))
    return (version_str, "")


def _extract_os_hints(banner: str) -> tuple[str, str, str]:
    """Extract (os_vendor, os_product, os_version) from service banners."""
    if not banner:
        return ("", "", "")

    m = re.search(r'Ubuntu[- ]?(\S*)', banner, re.IGNORECASE)
    if m:
        return ("Canonical", "Ubuntu", m.group(1).rstrip(")"))

    m = re.search(r'Debian[- ]?(\S*)', banner, re.IGNORECASE)
    if m:
        return ("Debian", "Debian", m.group(1).rstrip(")"))

    m = re.search(r'(?:CentOS|el)[\s._-]?(\d[\d.]*)', banner, re.IGNORECASE)
    if m:
        return ("CentOS", "CentOS", m.group(1))

    m = re.search(r'Windows\s+(\S+)', banner, re.IGNORECASE)
    if m:
        return ("Microsoft", "Windows", m.group(1))

    return ("", "", "")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="EASM Asset Normalizer")
    parser.add_argument("--dns", help="dnsx JSONL output")
    parser.add_argument("--asn", help="enrich_asn JSONL output")
    parser.add_argument("--rdns", help="dnsx PTR JSONL output")
    parser.add_argument("--ports", help="naabu JSONL output")
    parser.add_argument("--http", help="httpx JSONL output")
    parser.add_argument("--tls", help="tlsx JSONL output")
    parser.add_argument("--nerva", help="nerva JSONL output")
    parser.add_argument("--zgrab", action="append", default=[], help="zgrab2 JSONL output (can repeat)")
    parser.add_argument("--nuclei", help="nuclei JSONL output")
    parser.add_argument("--subzy", help="subzy JSON output")
    parser.add_argument("--cmdb", help="CMDB CSV export")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    parser.add_argument("--scan-id", default=now_iso(), help="Scan identifier")
    args = parser.parse_args()

    store = AssetStore(scan_id=args.scan_id)

    # Ingest in pipeline order
    if args.dns:
        print(f"Ingesting DNS: {args.dns}", file=sys.stderr)
        store.ingest_dns(read_jsonl(args.dns))

    if args.asn:
        print(f"Ingesting ASN: {args.asn}", file=sys.stderr)
        store.ingest_asn(read_jsonl(args.asn))

    if args.rdns:
        print(f"Ingesting rDNS: {args.rdns}", file=sys.stderr)
        store.ingest_rdns(read_jsonl(args.rdns))

    if args.ports:
        print(f"Ingesting ports: {args.ports}", file=sys.stderr)
        store.ingest_ports(read_jsonl(args.ports))

    if args.http:
        print(f"Ingesting HTTP: {args.http}", file=sys.stderr)
        store.ingest_http(read_jsonl(args.http))

    if args.tls:
        print(f"Ingesting TLS: {args.tls}", file=sys.stderr)
        store.ingest_tls(read_jsonl(args.tls))

    if args.nerva:
        print(f"Ingesting nerva: {args.nerva}", file=sys.stderr)
        store.ingest_nerva(read_jsonl(args.nerva))

    for zgrab_file in args.zgrab:
        # Extract module name from filename: zgrab_ssh.jsonl → ssh
        module = Path(zgrab_file).stem.replace("zgrab_", "")
        print(f"Ingesting zgrab2 ({module}): {zgrab_file}", file=sys.stderr)
        store.ingest_zgrab(read_jsonl(zgrab_file), module)

    if args.nuclei:
        print(f"Ingesting nuclei: {args.nuclei}", file=sys.stderr)
        store.ingest_nuclei(read_jsonl(args.nuclei))

    if args.subzy:
        print(f"Ingesting subzy: {args.subzy}", file=sys.stderr)
        data = read_json_file(args.subzy)
        store.ingest_subzy(data)

    # CDN enrichment (multi-signal, runs after all data sources ingested)
    try:
        store.enrich_cdn()
    except ImportError:
        print("WARN: detect_cdn module not found — skipping CDN enrichment", file=sys.stderr)

    # Shared hosting detection (runs after CDN so CDN assets are excluded)
    store.enrich_shared_hosting()

    # CMDB reconciliation
    if args.cmdb:
        print(f"Reconciling CMDB: {args.cmdb}", file=sys.stderr)
        cmdb = read_cmdb_csv(args.cmdb)
        store.reconcile_cmdb(cmdb)

    # Export
    store.export_jsonl(args.output)

    # Print summary
    summary = store.summary()
    print("\n=== Normalization Summary ===", file=sys.stderr)
    for k, v in summary.items():
        print(f"  {k}: {v}", file=sys.stderr)
    print(f"\nOutput: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
