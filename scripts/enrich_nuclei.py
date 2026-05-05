#!/usr/bin/env python3
"""
Build context-aware nuclei scan jobs from prior pipeline stages.

Reads httpx.jsonl, nerva.jsonl, and tls.jsonl to map discovered technologies
and services to targeted nuclei template tags.  Outputs a JSON file where each
entry is a nuclei "job" with a target list and tag filter.

Usage:
    python3 enrich_nuclei.py \
        --httpx data/output/httpx.jsonl \
        --nerva data/output/nerva.jsonl \
        --tls   data/output/tls.jsonl \
        --output data/output/nuclei_jobs.json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# httpx technology name (lowercased, version-stripped) → nuclei tag(s).
# Keys are matched as substrings against the normalized tech name.
TECH_TAG_MAP = {
    "jenkins": "jenkins",
    "wordpress": "wordpress,wp-plugin",
    "phpmyadmin": "phpmyadmin",
    "apache": "apache",
    "nginx": "nginx",
    "tomcat": "tomcat",
    "joomla": "joomla",
    "drupal": "drupal",
    "grafana": "grafana",
    "kibana": "kibana",
    "elasticsearch": "elasticsearch",
    "gitlab": "gitlab",
    "jira": "jira,atlassian",
    "confluence": "confluence,atlassian",
    "bitbucket": "bitbucket,atlassian",
    "sonarqube": "sonarqube",
    "harbor": "harbor",
    "spring": "spring",
    "struts": "struts",
    "laravel": "laravel",
    "django": "django",
    "iis": "iis",
    "weblogic": "weblogic",
    "websphere": "websphere",
    "coldfusion": "coldfusion",
    "jetty": "jetty",
    "moodle": "moodle",
    "magento": "magento",
    "sharepoint": "sharepoint",
    "exchange": "exchange",
    "citrix": "citrix",
    "fortinet": "fortinet",
    "paloalto": "paloalto",
    "sophos": "sophos",
    "vmware": "vmware",
    "vcenter": "vcenter",
    "cisco": "cisco",
    "mikrotik": "mikrotik",
    "amazon s3": "s3,aws",
    "amazon web services": "aws",
    "php": "php",
    "java": "java",
}

# nerva protocol → nuclei tag(s) for network-level templates.
SERVICE_TAG_MAP = {
    "mysql": "mysql",
    "postgresql": "postgres",
    "redis": "redis",
    "mongodb": "mongodb",
    "ftp": "ftp",
    "ssh": "ssh",
    "smtp": "smtp",
    "snmp": "snmp",
    "ldap": "ldap",
    "smb": "smb",
    "mssql": "mssql",
    "memcached": "memcached",
    "vnc": "vnc",
    "rdp": "rdp",
    "telnet": "telnet",
    "docker": "docker",
    "kubernetes": "kubernetes",
}


def normalize_tech(tech_name: str) -> str:
    return re.sub(r"[:/].*$", "", tech_name).strip().lower()


def build_jobs(httpx_path, nerva_path, tls_path, ports_path):
    jobs = []

    # --- httpx technologies → URL groups ---
    tech_urls: dict[str, set[str]] = defaultdict(set)
    if httpx_path and Path(httpx_path).exists():
        with open(httpx_path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = d.get("url", "")
                if not url:
                    continue
                for tech in d.get("tech", []):
                    norm = normalize_tech(tech)
                    for key, tags in TECH_TAG_MAP.items():
                        if key in norm:
                            tech_urls[tags].add(url)
                            break

    for tags, urls in sorted(tech_urls.items()):
        if urls:
            jobs.append({
                "label": tags.split(",")[0],
                "tags": tags,
                "type": "http",
                "targets": sorted(urls),
            })

    # --- nerva services → host:port (skip http/https, already covered above) ---
    svc_targets: dict[str, set[str]] = defaultdict(set)
    if nerva_path and Path(nerva_path).exists():
        with open(nerva_path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                proto = d.get("protocol", "").lower()
                host = d.get("host", "")
                port = d.get("port", "")
                if not host or not port or proto in ("http", "https"):
                    continue
                for key, tags in SERVICE_TAG_MAP.items():
                    if key == proto:
                        svc_targets[tags].add(f"{host}:{port}")
                        break

    for tags, targets in sorted(svc_targets.items()):
        if targets:
            jobs.append({
                "label": tags,
                "tags": tags,
                "type": "network",
                "targets": sorted(targets),
            })

    # --- TLS issues → targeted ssl scans ---
    tls_targets: set[str] = set()
    if tls_path and Path(tls_path).exists():
        with open(tls_path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = d.get("host", "")
                port = d.get("port", "")
                has_issue = (
                    d.get("self_signed")
                    or d.get("expired")
                    or d.get("mismatched")
                    or d.get("revoked")
                    or d.get("untrusted")
                )
                if host and port and has_issue:
                    tls_targets.add(f"{host}:{port}")

    if tls_targets:
        jobs.append({
            "label": "tls-issues",
            "tags": "ssl,tls",
            "type": "network",
            "targets": sorted(tls_targets),
        })

    return jobs


def main():
    ap = argparse.ArgumentParser(description="Build context-aware nuclei scan jobs")
    ap.add_argument("--httpx", help="Path to httpx.jsonl")
    ap.add_argument("--nerva", help="Path to nerva.jsonl")
    ap.add_argument("--tls", help="Path to tls.jsonl")
    ap.add_argument("--ports", help="Path to ports.jsonl (reserved for future use)")
    ap.add_argument("--output", required=True, help="Output JSON file")
    args = ap.parse_args()

    jobs = build_jobs(args.httpx, args.nerva, args.tls, args.ports)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(jobs, indent=2))

    total = sum(len(j["targets"]) for j in jobs)
    print(f"Generated {len(jobs)} nuclei jobs covering {total} targets", file=sys.stderr)
    for job in jobs:
        print(
            f"  {job['label']}: {len(job['targets'])} targets → tags={job['tags']}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    sys.exit(main())
