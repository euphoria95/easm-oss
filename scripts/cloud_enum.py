#!/usr/bin/env python3
"""
EASM Pipeline — Cloud Endpoint Enumeration

Identifies Azure and other cloud provider endpoints from DNS, HTTP, and TLS
pipeline data. Detects storage blobs, web apps, databases, CDN endpoints,
and other cloud-specific services.

Usage:
    python3 cloud_enum.py \
        --dns data/output/dns.jsonl \
        --http data/output/httpx.jsonl \
        --tls data/output/tls.jsonl \
        --output data/output/cloud_enum.jsonl
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Cloud endpoint CNAME / hostname patterns
# ---------------------------------------------------------------------------

AZURE_PATTERNS: dict[str, dict] = {
    # Storage
    ".blob.core.windows.net": {
        "provider": "azure",
        "service": "blob_storage",
        "risk": "medium",
        "description": "Azure Blob Storage",
    },
    ".file.core.windows.net": {
        "provider": "azure",
        "service": "file_storage",
        "risk": "medium",
        "description": "Azure File Storage",
    },
    ".queue.core.windows.net": {
        "provider": "azure",
        "service": "queue_storage",
        "risk": "low",
        "description": "Azure Queue Storage",
    },
    ".table.core.windows.net": {
        "provider": "azure",
        "service": "table_storage",
        "risk": "low",
        "description": "Azure Table Storage",
    },
    ".dfs.core.windows.net": {
        "provider": "azure",
        "service": "data_lake",
        "risk": "medium",
        "description": "Azure Data Lake Storage Gen2",
    },
    # Web / Compute
    ".azurewebsites.net": {
        "provider": "azure",
        "service": "app_service",
        "risk": "info",
        "description": "Azure App Service",
    },
    ".scm.azurewebsites.net": {
        "provider": "azure",
        "service": "app_service_scm",
        "risk": "high",
        "description": "Azure App Service SCM/Kudu (deployment endpoint)",
    },
    ".azurestaticapps.net": {
        "provider": "azure",
        "service": "static_web_app",
        "risk": "info",
        "description": "Azure Static Web Apps",
    },
    ".cloudapp.azure.com": {
        "provider": "azure",
        "service": "cloud_service",
        "risk": "info",
        "description": "Azure Cloud Service / VM",
    },
    ".azurecontainer.io": {
        "provider": "azure",
        "service": "container_instance",
        "risk": "medium",
        "description": "Azure Container Instances",
    },
    # CDN / Front Door / Traffic Manager
    ".azureedge.net": {
        "provider": "azure",
        "service": "cdn",
        "risk": "info",
        "description": "Azure CDN",
    },
    ".azurefd.net": {
        "provider": "azure",
        "service": "front_door",
        "risk": "info",
        "description": "Azure Front Door",
    },
    ".trafficmanager.net": {
        "provider": "azure",
        "service": "traffic_manager",
        "risk": "info",
        "description": "Azure Traffic Manager",
    },
    # Database
    ".database.windows.net": {
        "provider": "azure",
        "service": "sql_database",
        "risk": "high",
        "description": "Azure SQL Database",
    },
    ".documents.azure.com": {
        "provider": "azure",
        "service": "cosmosdb",
        "risk": "high",
        "description": "Azure Cosmos DB",
    },
    ".redis.cache.windows.net": {
        "provider": "azure",
        "service": "redis_cache",
        "risk": "medium",
        "description": "Azure Redis Cache",
    },
    ".mongo.cosmos.azure.com": {
        "provider": "azure",
        "service": "cosmosdb_mongo",
        "risk": "high",
        "description": "Azure Cosmos DB (MongoDB API)",
    },
    # API / Integration
    ".azure-api.net": {
        "provider": "azure",
        "service": "api_management",
        "risk": "medium",
        "description": "Azure API Management",
    },
    ".servicebus.windows.net": {
        "provider": "azure",
        "service": "service_bus",
        "risk": "medium",
        "description": "Azure Service Bus",
    },
    ".azurecr.io": {
        "provider": "azure",
        "service": "container_registry",
        "risk": "high",
        "description": "Azure Container Registry",
    },
    # Identity / Auth
    ".b2clogin.com": {
        "provider": "azure",
        "service": "ad_b2c",
        "risk": "medium",
        "description": "Azure AD B2C",
    },
    ".onmicrosoft.com": {
        "provider": "azure",
        "service": "azure_ad",
        "risk": "info",
        "description": "Azure Active Directory tenant",
    },
    # Key Vault
    ".vault.azure.net": {
        "provider": "azure",
        "service": "key_vault",
        "risk": "critical",
        "description": "Azure Key Vault",
    },
    # Search / AI
    ".search.windows.net": {
        "provider": "azure",
        "service": "cognitive_search",
        "risk": "medium",
        "description": "Azure Cognitive Search",
    },
    ".cognitiveservices.azure.com": {
        "provider": "azure",
        "service": "cognitive_services",
        "risk": "medium",
        "description": "Azure Cognitive Services",
    },
    ".openai.azure.com": {
        "provider": "azure",
        "service": "openai",
        "risk": "high",
        "description": "Azure OpenAI Service",
    },
}

AWS_PATTERNS: dict[str, dict] = {
    ".s3.amazonaws.com": {
        "provider": "aws",
        "service": "s3",
        "risk": "medium",
        "description": "AWS S3 Bucket",
    },
    ".s3-website": {
        "provider": "aws",
        "service": "s3_website",
        "risk": "medium",
        "description": "AWS S3 Static Website",
    },
    ".elasticbeanstalk.com": {
        "provider": "aws",
        "service": "elastic_beanstalk",
        "risk": "info",
        "description": "AWS Elastic Beanstalk",
    },
    ".cloudfront.net": {
        "provider": "aws",
        "service": "cloudfront",
        "risk": "info",
        "description": "AWS CloudFront CDN",
    },
    ".amazonaws.com": {
        "provider": "aws",
        "service": "generic",
        "risk": "info",
        "description": "AWS Generic Endpoint",
    },
    ".awsapprunner.com": {
        "provider": "aws",
        "service": "app_runner",
        "risk": "info",
        "description": "AWS App Runner",
    },
    ".rds.amazonaws.com": {
        "provider": "aws",
        "service": "rds",
        "risk": "high",
        "description": "AWS RDS Database",
    },
    ".elb.amazonaws.com": {
        "provider": "aws",
        "service": "elb",
        "risk": "info",
        "description": "AWS Elastic Load Balancer",
    },
    ".execute-api.": {
        "provider": "aws",
        "service": "api_gateway",
        "risk": "medium",
        "description": "AWS API Gateway",
    },
    ".lambda-url.": {
        "provider": "aws",
        "service": "lambda",
        "risk": "medium",
        "description": "AWS Lambda Function URL",
    },
}

GCP_PATTERNS: dict[str, dict] = {
    ".appspot.com": {
        "provider": "gcp",
        "service": "app_engine",
        "risk": "info",
        "description": "GCP App Engine",
    },
    ".run.app": {
        "provider": "gcp",
        "service": "cloud_run",
        "risk": "info",
        "description": "GCP Cloud Run",
    },
    ".cloudfunctions.net": {
        "provider": "gcp",
        "service": "cloud_functions",
        "risk": "medium",
        "description": "GCP Cloud Functions",
    },
    ".firebaseapp.com": {
        "provider": "gcp",
        "service": "firebase",
        "risk": "info",
        "description": "Google Firebase",
    },
    ".web.app": {
        "provider": "gcp",
        "service": "firebase_hosting",
        "risk": "info",
        "description": "Firebase Hosting",
    },
    ".storage.googleapis.com": {
        "provider": "gcp",
        "service": "cloud_storage",
        "risk": "medium",
        "description": "GCP Cloud Storage",
    },
}

ALL_PATTERNS = {**AZURE_PATTERNS, **AWS_PATTERNS, **GCP_PATTERNS}

# ---------------------------------------------------------------------------
# HTTP header patterns for cloud provider detection
# ---------------------------------------------------------------------------

CLOUD_HEADERS: list[tuple[str, str, str, str]] = [
    # (header_name, regex_pattern, provider, service)
    ("x-azure-ref", r".", "azure", "front_door"),
    ("x-msedge-ref", r".", "azure", "cdn"),
    ("x-ms-request-id", r".", "azure", "generic"),
    ("x-amz-request-id", r".", "aws", "s3"),
    ("x-amz-cf-id", r".", "aws", "cloudfront"),
    ("x-amz-cf-pop", r".", "aws", "cloudfront"),
    ("x-goog-generation", r".", "gcp", "cloud_storage"),
    ("x-goog-stored-content-length", r".", "gcp", "cloud_storage"),
    ("server", r"(?i)microsoft-azure", "azure", "generic"),
    ("server", r"(?i)AmazonS3", "aws", "s3"),
    ("server", r"(?i)UploadServer", "gcp", "cloud_storage"),
]


def _match_hostname(hostname: str) -> list[dict]:
    """Match a hostname against all cloud patterns. Return list of matches."""
    matches = []
    hostname = hostname.lower().rstrip(".")
    for pattern, meta in ALL_PATTERNS.items():
        if pattern in hostname:
            # Extract the resource name from the hostname
            resource_name = hostname.split(pattern)[0].rstrip(".")
            matches.append({
                **meta,
                "pattern": pattern,
                "hostname": hostname,
                "resource_name": resource_name,
            })
    return matches


def _match_headers(headers: dict) -> list[dict]:
    """Match HTTP response headers against cloud patterns."""
    matches = []
    for hdr_name, hdr_pattern, provider, service in CLOUD_HEADERS:
        val = headers.get(hdr_name, "")
        if val and re.search(hdr_pattern, val):
            matches.append({
                "provider": provider,
                "service": service,
                "signal": f"header:{hdr_name}",
            })
    return matches


def enumerate_cloud(dns_path=None, http_path=None, tls_path=None):
    """Enumerate cloud endpoints from pipeline outputs.

    Returns a list of cloud_enum records, one per discovered endpoint.
    """
    results: dict[str, dict] = {}  # keyed by fqdn+service for dedup
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _add(fqdn, entry, source):
        key = f"{fqdn}:{entry['provider']}:{entry['service']}"
        if key not in results:
            results[key] = {
                "fqdn": fqdn,
                "provider": entry["provider"],
                "service": entry["service"],
                "service_label": entry.get("description", entry["service"]),
                "risk": entry.get("risk", "info"),
                "resource_name": entry.get("resource_name", ""),
                "hostname": entry.get("hostname", ""),
                "pattern": entry.get("pattern", ""),
                "signals": [source],
                "timestamp": timestamp,
            }
        else:
            if source not in results[key]["signals"]:
                results[key]["signals"].append(source)

    # --- DNS records: check FQDN and CNAME chains ---
    if dns_path and Path(dns_path).exists():
        with open(dns_path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                host = rec.get("host", "").lower()

                # Check the FQDN itself
                for match in _match_hostname(host):
                    _add(host, match, "dns_fqdn")

                # Check CNAME chain
                cnames = rec.get("cname", [])
                if isinstance(cnames, str):
                    cnames = [cnames]
                for cname in cnames:
                    for match in _match_hostname(cname):
                        _add(host, match, f"dns_cname:{cname}")

    # --- HTTP: check URLs, final_url, response headers ---
    if http_path and Path(http_path).exists():
        with open(http_path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                url = rec.get("url", "")
                host = rec.get("input", "").split(":")[0] if ":" in rec.get("input", "") else ""
                if not host and "://" in url:
                    host = url.split("://")[1].split("/")[0].split(":")[0]
                if not host:
                    host = rec.get("host", "")
                host = host.lower()

                # Check URL hostname
                if url:
                    url_host = url.split("://")[1].split("/")[0].split(":")[0] if "://" in url else ""
                    if url_host:
                        for match in _match_hostname(url_host):
                            _add(host or url_host, match, "http_url")

                # Check final URL (redirect target)
                final_url = rec.get("final_url") or rec.get("location", "")
                if final_url and "://" in final_url:
                    final_host = final_url.split("://")[1].split("/")[0].split(":")[0]
                    for match in _match_hostname(final_host):
                        _add(host, match, f"http_redirect:{final_host}")

                # Check CNAME from httpx
                for cname in (rec.get("cname") or []):
                    if isinstance(cname, str):
                        for match in _match_hostname(cname):
                            _add(host, match, f"http_cname:{cname}")

                # Check response headers
                raw_headers = rec.get("header", {}) or {}
                if isinstance(raw_headers, str):
                    parsed = {}
                    for hdr_line in raw_headers.split("\n"):
                        if ":" in hdr_line:
                            k, v = hdr_line.split(":", 1)
                            parsed[k.strip().lower()] = v.strip()
                    raw_headers = parsed
                for hdr_match in _match_headers(raw_headers):
                    _add(host, {**hdr_match, "risk": "info", "description": f"{hdr_match['provider']} ({hdr_match['signal']})"}, hdr_match["signal"])

    # --- TLS: check SANs for cloud endpoints ---
    if tls_path and Path(tls_path).exists():
        with open(tls_path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                host = rec.get("host", "").split(":")[0].lower()
                sans = rec.get("san") or rec.get("subject_an") or []
                if isinstance(sans, str):
                    sans = [sans]

                for san in sans:
                    san_clean = san.lower().strip().lstrip("*.")
                    for match in _match_hostname(san_clean):
                        _add(host or san_clean, match, f"tls_san:{san_clean}")

    return list(results.values())


def main():
    ap = argparse.ArgumentParser(description="Enumerate cloud endpoints from pipeline data")
    ap.add_argument("--dns", help="Path to dns.jsonl")
    ap.add_argument("--http", help="Path to httpx.jsonl")
    ap.add_argument("--tls", help="Path to tls.jsonl")
    ap.add_argument("--output", required=True, help="Output JSONL path")
    args = ap.parse_args()

    results = enumerate_cloud(args.dns, args.http, args.tls)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        for rec in results:
            f.write(json.dumps(rec) + "\n")

    # Summary
    provider_counts = defaultdict(int)
    service_counts = defaultdict(int)
    risk_counts = defaultdict(int)
    for r in results:
        provider_counts[r["provider"]] += 1
        service_counts[f"{r['provider']}:{r['service']}"] += 1
        risk_counts[r["risk"]] += 1

    print(f"\nCloud Enumeration Complete", file=sys.stderr)
    print(f"  Total endpoints: {len(results)}", file=sys.stderr)
    for provider, count in sorted(provider_counts.items()):
        print(f"  {provider}: {count}", file=sys.stderr)
    if risk_counts:
        print(f"  Risk: {dict(risk_counts)}", file=sys.stderr)


if __name__ == "__main__":
    main()
