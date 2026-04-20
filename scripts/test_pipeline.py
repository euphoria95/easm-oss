#!/usr/bin/env python3
"""
EASM Pipeline — Test with Synthetic Data

Generates realistic synthetic scan outputs and runs the normalizer + DuckDB
loader to validate the full pipeline without actual scanning.

Usage:
    python3 test_pipeline.py [--assets 50] [--output-dir data/output]
"""

import argparse
import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


SAMPLE_DOMAINS = [
    "portal.example.com", "api.example.com", "mail.example.com",
    "vpn.example.com", "dev.example.com", "staging.example.com",
    "admin.example.com", "blog.example.com", "shop.example.com",
    "docs.example.com", "ci.example.com", "jenkins.example.com",
    "grafana.example.com", "kibana.example.com", "prometheus.example.com",
    "auth.example.com", "sso.example.com", "cdn.example.com",
    "assets.example.com", "static.example.com", "ws.example.com",
    "status.example.com", "beta.example.com", "test.example.com",
    "sandbox.example.com", "demo.example.com", "internal.example.com",
    "backup.example.com", "old.example.com", "legacy.example.com",
    "new.example.com", "app.example.com", "mobile-api.example.com",
    "webhooks.example.com", "upload.example.com", "download.example.com",
    "reports.example.com", "analytics.example.com", "metrics.example.com",
    "logs.example.com", "queue.example.com", "cache.example.com",
    "db-admin.example.com", "phpmyadmin.example.com", "git.example.com",
    "registry.example.com", "npm.example.com", "docker.example.com",
    "k8s.example.com", "rancher.example.com", "vault.example.com",
]

TECHNOLOGIES = [
    "Nginx", "Apache", "Cloudflare", "React", "Angular", "Vue.js",
    "Node.js", "Express", "Django", "Flask", "Spring Boot", "WordPress",
    "Grafana", "Kibana", "Jenkins", "GitLab", "Jira", "Confluence",
    "PHP", "Ruby on Rails", "IIS", "Tomcat", "HAProxy", "Varnish",
]

CDN_PROVIDERS = ["cloudflare", "akamai", "fastly", "cloudfront", None, None]

ASN_ORGS = [
    ("13335", "CLOUDFLARENET"),
    ("16509", "AMAZON-02"),
    ("15169", "GOOGLE"),
    ("8075", "MICROSOFT-CORP-MSN-AS-BLOCK"),
    ("20940", "AKAMAI-ASN1"),
    ("14618", "AMAZON-AES"),
]

NUCLEI_TEMPLATES = [
    ("exposed-panels/grafana-login", "Grafana Login Panel", "low"),
    ("exposed-panels/jenkins-login", "Jenkins Login Panel", "low"),
    ("exposed-panels/phpmyadmin-panel", "phpMyAdmin Panel", "medium"),
    ("exposures/configs/git-config", "Git Config Exposure", "medium"),
    ("exposures/files/ds-store", ".DS_Store File", "info"),
    ("exposures/files/env-file", ".env File Exposure", "high"),
    ("misconfiguration/http-missing-security-headers", "Missing Security Headers", "info"),
    ("takeovers/s3-takeover", "S3 Subdomain Takeover", "high"),
    ("takeovers/cname-service-detection", "CNAME Service Detection", "info"),
    ("default-logins/admin-admin", "Default Admin Credentials", "critical"),
    ("technologies/nginx-version", "Nginx Version Detection", "info"),
    ("technologies/apache-version", "Apache Version Detection", "info"),
]


def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_date_recent(days_back=90):
    dt = datetime.now(timezone.utc) - timedelta(days=random.randint(0, days_back))
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_dns(domains, output_path):
    records = []
    for domain in domains:
        if random.random() < 0.05:  # 5% don't resolve
            continue
        ip = random_ip()
        rec = {
            "host": domain,
            "a": [ip],
            "aaaa": [],
            "cname": [f"edge.cdn.example.net"] if random.random() < 0.3 else [],
            "ns": ["ns1.example.com", "ns2.example.com"],
            "mx": ["mail.example.com"] if "mail" in domain else [],
            "status_code": "NOERROR",
            "resolver": ["8.8.8.8:53"],
            "timestamp": random_date_recent(),
        }
        records.append(rec)

    with open(output_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return records


def generate_ports(dns_records, output_path):
    records = []
    common_ports = [22, 80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 9090, 9200]

    for dns_rec in dns_records:
        host = dns_rec["host"]
        # Every host has at least 80/443
        ports = [80, 443]
        # Random additional ports
        for p in common_ports[2:]:
            if random.random() < 0.15:
                ports.append(p)

        for port in ports:
            records.append({
                "host": host,
                "ip": dns_rec["a"][0] if dns_rec["a"] else random_ip(),
                "port": port,
                "protocol": "tcp",
                "timestamp": random_date_recent(),
            })

    with open(output_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return records


def generate_httpx(port_records, output_path, screenshot_dir):
    records = []
    web_ports = {80, 81, 443, 3000, 8080, 8443, 9090}

    for prec in port_records:
        if prec["port"] not in web_ports:
            continue

        host = prec["host"]
        port = prec["port"]
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}{':%d' % port if port not in (80, 443) else ''}/"

        asn = random.choice(ASN_ORGS)
        cdn = random.choice(CDN_PROVIDERS)
        techs = random.sample(TECHNOLOGIES, k=random.randint(1, 4))

        rec = {
            "url": url,
            "input": f"{host}:{port}",
            "host": prec["ip"],
            "port": port,
            "scheme": scheme,
            "status_code": random.choice([200, 200, 200, 301, 302, 403, 404]),
            "title": f"{host.split('.')[0].title()} - Example Corp",
            "webserver": random.choice(["nginx/1.24.0", "Apache/2.4.58", "cloudflare", "Microsoft-IIS/10.0"]),
            "content_type": "text/html; charset=utf-8",
            "content_length": random.randint(1000, 50000),
            "response_time": f"{random.randint(50, 500)}ms",
            "tech": techs,
            "favicon": random.choice([-1340235546, -527603117, 88733652, None]),
            "hash": {"body_sha256": f"{''.join(random.choices('0123456789abcdef', k=64))}"},
            "asn": {"as_number": int(asn[0]), "as_name": asn[1], "as_country": "US"},
            "cdn_name": cdn,
            "cdn": cdn is not None,
            "jarm": f"{''.join(random.choices('0123456789abcdef', k=62))}",
            "http2": random.random() < 0.6,
            "method": "GET",
            "chain": [url] if random.random() < 0.7 else [url, url + "login"],
            "timestamp": random_date_recent(),
        }

        # Simulate screenshot
        screenshot_path = Path(screenshot_dir) / f"{host}_{port}.png"
        rec["screenshot_path"] = str(screenshot_path)

        records.append(rec)

    with open(output_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return records


def generate_tls(port_records, output_path):
    records = []
    tls_ports = {443, 8443, 465, 993, 995}

    for prec in port_records:
        if prec["port"] not in tls_ports:
            continue

        host = prec["host"]
        days_to_expiry = random.randint(-30, 365)
        not_after = (datetime.now(timezone.utc) + timedelta(days=days_to_expiry)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_before = (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%dT%H:%M:%SZ")

        rec = {
            "host": f"{host}:{prec['port']}",
            "port": prec["port"],
            "tls_version": random.choice(["TLS1.2", "TLS1.3", "TLS1.3"]),
            "cipher": random.choice(["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-AES256-GCM-SHA384"]),
            "jarm": f"{''.join(random.choices('0123456789abcdef', k=62))}",
            "issuer_dn": random.choice([
                "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
                "CN=Cloudflare Inc ECC CA-3,O=Cloudflare\\, Inc.,C=US",
                "CN=DigiCert SHA2 Extended Validation Server CA",
            ]),
            "subject_dn": f"CN={host}",
            "san": [host, f"*.{'.'.join(host.split('.')[1:])}"],
            "not_before": not_before,
            "not_after": not_after,
            "serial": f"{''.join(random.choices('0123456789abcdef', k=32))}",
            "expired": days_to_expiry < 0,
            "self_signed": random.random() < 0.05,
            "mismatched": random.random() < 0.03,
            "revoked": False,
            "untrusted": random.random() < 0.02,
            "wildcard_cert": random.random() < 0.4,
            "key_algo": random.choice(["RSA", "ECDSA"]),
            "key_size": random.choice([2048, 4096, 256]),
        }
        records.append(rec)

    with open(output_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return records


def generate_nuclei(httpx_records, output_path):
    records = []
    for hrec in httpx_records:
        # 30% chance of a finding
        if random.random() > 0.30:
            continue
        template = random.choice(NUCLEI_TEMPLATES)
        rec = {
            "template-id": template[0],
            "template": template[0].split("/")[-1],
            "info": {
                "name": template[1],
                "severity": template[2],
                "tags": [template[0].split("/")[0]],
                "description": f"Detected {template[1]}",
            },
            "host": hrec["url"].split("://")[1].split("/")[0].split(":")[0],
            "matched-at": hrec["url"],
            "timestamp": random_date_recent(),
        }
        records.append(rec)

    with open(output_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return records


def generate_zgrab_ssh(port_records, output_dir):
    records = []
    for prec in port_records:
        if prec["port"] != 22:
            continue
        rec = {
            "ip": prec["ip"],
            "domain": prec["host"],
            "data": {
                "ssh": {
                    "status": "success",
                    "result": {
                        "server_id": {
                            "raw": random.choice([
                                "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                                "SSH-2.0-OpenSSH_9.3p1 Debian-1",
                                "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
                            ]),
                        },
                    },
                },
            },
        }
        records.append(rec)

    output_path = Path(output_dir) / "zgrab_ssh.jsonl"
    with open(output_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return records


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic EASM test data")
    parser.add_argument("--assets", type=int, default=50, help="Number of assets")
    parser.add_argument("--output-dir", default="data/output", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    screenshot_dir = output_dir.parent / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    zgrab_dir = output_dir / "zgrab"
    zgrab_dir.mkdir(parents=True, exist_ok=True)

    # Select domains
    domains = SAMPLE_DOMAINS[:args.assets]
    if args.assets > len(SAMPLE_DOMAINS):
        for i in range(args.assets - len(SAMPLE_DOMAINS)):
            domains.append(f"auto-{i}.example.com")

    print(f"Generating synthetic data for {len(domains)} domains...", file=sys.stderr)

    # Generate each stage
    dns_recs = generate_dns(domains, output_dir / "dns.jsonl")
    print(f"  DNS: {len(dns_recs)} records", file=sys.stderr)

    port_recs = generate_ports(dns_recs, output_dir / "ports.jsonl")
    print(f"  Ports: {len(port_recs)} records", file=sys.stderr)

    httpx_recs = generate_httpx(port_recs, output_dir / "httpx.jsonl", screenshot_dir)
    print(f"  HTTP: {len(httpx_recs)} records", file=sys.stderr)

    tls_recs = generate_tls(port_recs, output_dir / "tls.jsonl")
    print(f"  TLS: {len(tls_recs)} records", file=sys.stderr)

    nuclei_recs = generate_nuclei(httpx_recs, output_dir / "nuclei.jsonl")
    print(f"  Nuclei: {len(nuclei_recs)} records", file=sys.stderr)

    zgrab_recs = generate_zgrab_ssh(port_recs, zgrab_dir)
    print(f"  zgrab2 SSH: {len(zgrab_recs)} records", file=sys.stderr)

    print(f"\nSynthetic data written to {output_dir}/", file=sys.stderr)
    print("Run the normalizer:", file=sys.stderr)
    print(f"  python3 scripts/normalize.py \\", file=sys.stderr)
    print(f"    --dns {output_dir}/dns.jsonl \\", file=sys.stderr)
    print(f"    --ports {output_dir}/ports.jsonl \\", file=sys.stderr)
    print(f"    --http {output_dir}/httpx.jsonl \\", file=sys.stderr)
    print(f"    --tls {output_dir}/tls.jsonl \\", file=sys.stderr)
    print(f"    --zgrab {zgrab_dir}/zgrab_ssh.jsonl \\", file=sys.stderr)
    print(f"    --nuclei {output_dir}/nuclei.jsonl \\", file=sys.stderr)
    print(f"    --cmdb data/input/cmdb_export.csv \\", file=sys.stderr)
    print(f"    --output {output_dir}/assets.jsonl", file=sys.stderr)


if __name__ == "__main__":
    main()
